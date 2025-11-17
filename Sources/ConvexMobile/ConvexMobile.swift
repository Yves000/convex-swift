// The Swift Programming Language
// https://docs.swift.org/swift-book

import Combine
import Foundation
@_exported import UniFFI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(Network)
import Network
#endif

// MARK: - JWT Helper

private struct JWTDecoder {
  static func extractExpiration(from token: String) -> Date? {
    let segments = token.components(separatedBy: ".")
    guard segments.count >= 2 else {
      return nil
    }

    let payloadSegment = segments[1]
    var base64 = payloadSegment
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")

    let paddingLength = (4 - base64.count % 4) % 4
    base64 += String(repeating: "=", count: paddingLength)

    guard let payloadData = Data(base64Encoded: base64),
          let json = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
          let exp = json["exp"] as? TimeInterval else {
      return nil
    }

    return Date(timeIntervalSince1970: exp)
  }
}

// MARK: - Token Refresh Coordinator

/// Actor-based coordinator to prevent concurrent token refresh operations.
/// Ensures only one refresh can execute at a time, preventing race conditions
/// when multiple triggers (timer, app resume) attempt simultaneous refreshes.
private actor TokenRefreshCoordinator {
  private var isRefreshing = false
  private var lastRefreshAttempt: Date?
  private let minimumRefreshInterval: TimeInterval = 5.0

  func shouldPerformRefresh() -> Bool {
    if isRefreshing {
      return false
    }

    if let lastAttempt = lastRefreshAttempt {
      let timeSinceLastAttempt = Date().timeIntervalSince(lastAttempt)
      if timeSinceLastAttempt < minimumRefreshInterval {
        return false
      }
    }

    isRefreshing = true
    lastRefreshAttempt = Date()
    return true
  }

  func completeRefresh() {
    isRefreshing = false
  }
}

// MARK: - Token Refresh Manager

/// Manages automatic token refresh for authenticated Convex clients.
class TokenRefreshManager<T> {
  private let authProvider: any AuthProvider<T>
  private let onTokenRefreshed: (String) async throws -> Void
  private let onRefreshFailed: (Error) -> Void
  private var refreshTimer: AnyCancellable?
  private var currentAuthData: T?
  private let refreshLeewaySeconds: TimeInterval
  private let maxRetries: Int
  private let baseRetryDelay: TimeInterval
  private let refreshCoordinator = TokenRefreshCoordinator()
  #if canImport(UIKit)
  private var appLifecycleObserver: NSObjectProtocol?
  #endif
  #if canImport(Network)
  private var pathMonitor: NWPathMonitor?
  private var isWaitingForNetwork = false
  #endif

  init(
    authProvider: any AuthProvider<T>,
    refreshLeewaySeconds: TimeInterval = 60,
    onTokenRefreshed: @escaping (String) async throws -> Void,
    onRefreshFailed: @escaping (Error) -> Void,
    maxRetries: Int = 3,
    baseRetryDelay: TimeInterval = 2
  ) {
    self.authProvider = authProvider
    self.refreshLeewaySeconds = refreshLeewaySeconds
    self.onTokenRefreshed = onTokenRefreshed
    self.onRefreshFailed = onRefreshFailed
    self.maxRetries = maxRetries
    self.baseRetryDelay = baseRetryDelay

    #if canImport(UIKit)
    appLifecycleObserver = NotificationCenter.default.addObserver(
      forName: UIApplication.willEnterForegroundNotification,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      Task {
        await self?.handleAppResume()
      }
    }
    #endif
  }

  deinit {
    #if canImport(UIKit)
    if let observer = appLifecycleObserver {
      NotificationCenter.default.removeObserver(observer)
    }
    #endif
    #if canImport(Network)
    pathMonitor?.cancel()
    #endif
  }

  private func isOfflineError(_ error: Error) -> Bool {
    let nsError = error as NSError
    return nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorNotConnectedToInternet
  }

  private func isTransientError(_ error: Error) -> Bool {
    let nsError = error as NSError

    if nsError.domain == NSURLErrorDomain {
      switch nsError.code {
      case NSURLErrorTimedOut,
           NSURLErrorCannotConnectToHost,
           NSURLErrorNetworkConnectionLost,
           NSURLErrorSecureConnectionFailed,
           NSURLErrorServerCertificateUntrusted,
           NSURLErrorServerCertificateHasUnknownRoot,
           NSURLErrorServerCertificateNotYetValid,
           -1200:
        return true
      default:
        return false
      }
    }

    if nsError.domain == "kCFErrorDomainCFNetwork" || nsError.domain == String(kCFErrorDomainCFNetwork) {
      return abs(nsError.code) >= 9800 && abs(nsError.code) <= 9900
    }

    return false
  }

  private func isAuthenticationError(_ error: Error) -> Bool {
    let nsError = error as NSError

    if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorUserAuthenticationRequired {
      return true
    }

    let errorDescription = error.localizedDescription.lowercased()
    return errorDescription.contains("invalid_grant") ||
           errorDescription.contains("invalid_client") ||
           errorDescription.contains("unauthorized") ||
           errorDescription.contains("invalid_token") ||
           errorDescription.contains("refresh token already exchanged")
  }

  func startMonitoring(authData: T) {
    stopMonitoring()
    currentAuthData = authData

    let token = authProvider.extractIdToken(from: authData)
    guard let expirationDate = JWTDecoder.extractExpiration(from: token) else {
      return
    }

    let timeUntilExpiration = expirationDate.timeIntervalSinceNow
    let timeUntilRefresh = max(0, timeUntilExpiration - refreshLeewaySeconds)

    if timeUntilRefresh <= 0 {
      let networkStabilizationDelay: TimeInterval = 3.0
      Task { [weak self] in
        try? await Task.sleep(nanoseconds: UInt64(networkStabilizationDelay * 1_000_000_000))
        await self?.performRefreshWithRetry()
      }
      return
    }

    refreshTimer = Timer.publish(every: timeUntilRefresh, on: .main, in: .common)
      .autoconnect()
      .first()
      .sink { [weak self] _ in
        Task {
          await self?.performRefreshWithRetry()
        }
      }
  }

  func stopMonitoring() {
    refreshTimer?.cancel()
    refreshTimer = nil
    currentAuthData = nil
  }

  private func handleAppResume() async {
    guard let authData = currentAuthData else {
      return
    }

    let token = authProvider.extractIdToken(from: authData)
    guard let expirationDate = JWTDecoder.extractExpiration(from: token) else {
      return
    }

    let timeUntilExpiration = expirationDate.timeIntervalSinceNow
    if timeUntilExpiration <= refreshLeewaySeconds {
      await performRefreshWithRetry()
    }
  }

  #if canImport(Network)
  private func waitForNetworkAndRetry() async {
    guard !isWaitingForNetwork else {
      return
    }

    isWaitingForNetwork = true

    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
      let monitor = NWPathMonitor()
      pathMonitor = monitor

      monitor.pathUpdateHandler = { [weak self] path in
        guard let self = self else {
          continuation.resume()
          return
        }

        if path.status == .satisfied {
          self.pathMonitor?.cancel()
          self.pathMonitor = nil
          self.isWaitingForNetwork = false
          continuation.resume()
        }
      }

      let queue = DispatchQueue(label: "com.convex.network-monitor")
      monitor.start(queue: queue)
    }

    await performRefreshWithRetry()
  }
  #endif

  private func performRefreshWithRetry(retryAttempt: Int = 0) async {
    guard await refreshCoordinator.shouldPerformRefresh() else {
      return
    }

    await performRefreshOperation(retryAttempt: retryAttempt)
    await refreshCoordinator.completeRefresh()
  }

  private func performRefreshOperation(retryAttempt: Int) async {
    guard let authData = currentAuthData else {
      return
    }

    do {
      let newAuthData = try await authProvider.refreshToken(from: authData)
      let newToken = authProvider.extractIdToken(from: newAuthData)

      currentAuthData = newAuthData
      try await onTokenRefreshed(newToken)
      startMonitoring(authData: newAuthData)
    } catch AuthProviderError.refreshNotSupported {
      return
    } catch {
      let isOffline = isOfflineError(error)
      let isTransient = isTransientError(error)

      #if canImport(Network)
      if isOffline {
        await refreshCoordinator.completeRefresh()
        await waitForNetworkAndRetry()
        return
      }
      #endif

      let isAuthError = isAuthenticationError(error)

      if isAuthError {
        onRefreshFailed(error)
        return
      }

      if isTransient && retryAttempt < maxRetries {
        let delay = baseRetryDelay * pow(2.0, Double(retryAttempt))
        await refreshCoordinator.completeRefresh()
        try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        await performRefreshWithRetry(retryAttempt: retryAttempt + 1)
      } else if isTransient {
        // Max retries exceeded - keep user logged in, will retry on next scheduled refresh
      } else {
        onRefreshFailed(error)
      }
    }
  }
}

/// A client API for interacting with a Convex backend.
///
/// Handles marshalling of data between calling code and the
/// [convex-mobile](https://github.com/get-convex/convex-mobile) and
/// [convex-rs](https://github.com/get-convex/convex-rs) native libraries.
///
/// Consumers of this client should use Swift's ``Decodable``  protocol for handling data received from the
/// Convex backend.
public class ConvexClient {
  let ffiClient: UniFFI.MobileConvexClientProtocol
  fileprivate let webSocketStateAdapter = WebSocketStateAdapter()

  /// Creates a new instance of ``ConvexClient``.
  ///
  /// - Parameters:
  ///   - deploymentUrl: The Convex backend URL to connect to; find it in the [dashboard](https://dashboard.convex.dev) Settings for your project
  public init(deploymentUrl: String) {
    self.ffiClient = UniFFI.MobileConvexClient(
      deploymentUrl: deploymentUrl, clientId: "swift-\(convexMobileVersion)", webSocketStateSubscriber: webSocketStateAdapter)
  }

  init(ffiClient: UniFFI.MobileConvexClientProtocol) {
    self.ffiClient = ffiClient
  }

  /// Subscribes to the query with the given `name` and converts data from the subscription into an
  /// ``AnyPublisher<T, ClientError>``.
  ///
  /// The upstream Convex subscription will be canceled if whatever is subscribed to returned publisher
  /// stops listening.
  ///
  /// - Parameters:
  ///   - name: A value in "module:query_name"  format that will be used when calling the backend
  ///   - args: An optional ``Dictionary`` of arguments to be sent to the backend query function
  ///   - output: The type of data that will be returned in the Publisher, as a convenience to callers
  ///             where the type can't be easily inferred.
  public func subscribe<T: Decodable>(
    to name: String, with args: [String: ConvexEncodable?]? = nil, yielding output: T.Type? = nil
  ) -> AnyPublisher<T, ClientError> {
    // There are two steps to producing the final Publisher in this method.
    // 1. Subscribe to the data from Convex and publish the subscription handle
    // 2. Feed the subscription handle into the Convex data Publisher so it can cancel the upstream
    //    subscription when downstream subscribers are done consuming data

    // This Publisher will ultimately publish the data received from Convex.
    let convexPublisher = PassthroughSubject<T, ClientError>()
    let adapter = SubscriptionAdapter<T>(publisher: convexPublisher)

    // This Publisher is responsible for initializing the Convex subscription and returning a handle
    // to the upstream (Convex) subscription.
    let initializationPublisher = Future<SubscriptionHandle, ClientError> {
      result in
      Task {
        do {
          let subscriptionHandle = try await self.ffiClient.subscribe(
            name: name,
            args: args?.mapValues({ v in
              try v?.convexEncode() ?? "null"
            }) ?? [:], subscriber: adapter)
          result(.success(subscriptionHandle))
        } catch {
          result(.failure(ClientError.InternalError(msg: error.localizedDescription)))
        }
      }
    }

    // The final Publisher takes the handle from the initial Convex subscription and supplies it to
    // the data publisher so it can cancel the upstream subscription when consumers are no longer
    // listening for data.
    return initializationPublisher.flatMap({ subscriptionHandle in
      convexPublisher.handleEvents(receiveCancel: {
        subscriptionHandle.cancel()
      })
    })
    .eraseToAnyPublisher()
  }

  /// Executes the mutation with the given `name` and `args` and returns the result.
  ///
  /// For mutations that don't return a value, prefer calling the version of this method that doesn't return a value.
  ///
  /// - Parameters:
  ///   - name: A value in "module:mutation_name"  format that will be used when calling the backend
  ///   - args: An optional ``Dictionary`` of arguments to be sent to the backend mutation function
  public func mutation<T: Decodable>(_ name: String, with args: [String: ConvexEncodable?]? = nil)
    async throws -> T
  {
    try await callForResult(name: name, args: args, remoteCall: ffiClient.mutation)
  }

  /// Executes the mutation with the given `name` and `args` without returning a result.
  ///
  /// For mutations that return a value, prefer calling the version of this method that returns a ``Decodable`` value.
  ///
  /// - Parameters:
  ///   - name: A value in "module:mutation_name"  format that will be used when calling the backend
  ///   - args: An optional ``Dictionary`` of arguments to be sent to the backend mutation function
  public func mutation(_ name: String, with args: [String: ConvexEncodable?]? = nil)
    async throws
  {
    let _: String? = try await mutation(name, with: args)
  }

  /// Executes the action with the given `name` and `args` and returns the result.
  ///
  /// For actions that don't return a value, prefer calling the version of this method that doesn't return a value.
  ///
  /// - Parameters:
  ///   - name: A value in "module:mutation_name"  format that will be used when calling the backend
  ///   - args: An optional ``Dictionary`` of arguments to be sent to the backend mutation function
  public func action<T: Decodable>(_ name: String, with args: [String: ConvexEncodable?]? = nil)
    async throws -> T
  {
    return try await callForResult(name: name, args: args, remoteCall: ffiClient.action)
  }

  /// Executes the action with the given `name` and `args` without returning a result.
  ///
  /// For actions that return a value, prefer calling the version of this method that returns a ``Decodable`` value.
  ///
  /// - Parameters:
  ///   - name: A value in "module:mutation_name"  format that will be used when calling the backend
  ///   - args: An optional ``Dictionary`` of arguments to be sent to the backend mutation function
  public func action(_ name: String, with args: [String: ConvexEncodable?]? = nil)
    async throws
  {
    let _: String? = try await action(name, with: args)
  }

  /// Common handler for `action` and `mutation` calls.
  ///
  /// To the client code, both work in a very similar fashion where remote code is invoked and a result is returned. This handler takes care of
  /// encoding the arguments and decoding the result, whether the call is an `action` or `mutation`.
  func callForResult<T: Decodable>(
    name: String, args: [String: ConvexEncodable?]? = nil, remoteCall: RemoteCall
  )
    async throws -> T
  {
    let rawResult = try await remoteCall(
      name,
      args?.mapValues({ v in
        try v?.convexEncode() ?? "null"
      }) ?? [:])
    return try! JSONDecoder().decode(T.self, from: Data(rawResult.utf8))
  }

  typealias RemoteCall = (String, [String: String]) async throws -> String
  
  public func watchWebSocketState() -> AnyPublisher<WebSocketState, Never> {
    return webSocketStateAdapter.newPublisher()
  }
}

/// Authentication states that can be experienced when using an ``AuthProvider`` with
/// ``ConvexClientWithAuth``.
public enum AuthState<T> {
  /// Represents an authenticated user.
  ///
  /// Contains authentication data from the associated ``AuthProvider``.
  case authenticated(T)
  /// Represents an unauthenticated user.
  case unauthenticated
  /// Represents an ongoing authentication attempt.
  case loading
}

/// Errors that can occur during authentication operations.
public enum AuthProviderError: Error {
  /// The authentication provider does not support token refresh.
  case refreshNotSupported
}

/// An authentication provider, used with ``ConvexClientWithAuth``.
///
/// The generic type `T` is the data returned by the provider upon a successful authentication attempt.
public protocol AuthProvider<T> {
  associatedtype T

  /// Trigger a login flow, which might launch a new UI/screen.
  func login() async throws -> T
  /// Trigger a logout flow, which might launch a new UI/screen.
  func logout() async throws
  /// Trigger a cached, UI-less re-authentication ussing stored credentials from a previous ``login()``.
  func loginFromCache() async throws -> T
  /// Extracts a [JWT ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
  /// from the `authResult`.
  func extractIdToken(from authResult: T) -> String

  /// Refreshes the authentication data to obtain a new token.
  ///
  /// This method is called automatically by the client when the current token is about to expire.
  /// The default implementation throws ``AuthProviderError/refreshNotSupported``.
  ///
  /// Override this method if your authentication provider supports token refresh.
  ///
  /// - Parameter authResult: The current authentication data.
  /// - Returns: New authentication data with a fresh token.
  /// - Throws: ``AuthProviderError/refreshNotSupported`` by default, or other errors during refresh.
  func refreshToken(from authResult: T) async throws -> T
}

extension AuthProvider {
  public func refreshToken(from authResult: T) async throws -> T {
    throw AuthProviderError.refreshNotSupported
  }
}

/// Like ``ConvexClient``, but supports integration with an authentication provider via ``AuthProvider``.
///
/// The generic parameter `T` matches the type of data returned by the ``AuthProvider`` upon successful
/// authentication.
public class ConvexClientWithAuth<T>: ConvexClient {
  private let authPublisher = CurrentValueSubject<AuthState<T>, Never>(AuthState.unauthenticated)
  private let authProvider: any AuthProvider<T>
  private var tokenRefreshManager: TokenRefreshManager<T>?

  /// A publisher that updates with the current ``AuthState`` of this client instance.
  public let authState: AnyPublisher<AuthState<T>, Never>

  /// Creates a new instance of ``ConvexClientWithAuth``.
  ///
  /// - Parameters:
  ///   - deploymentUrl: The Convex backend URL to connect to; find it in the [dashboard](https://dashboard.convex.dev) Settings for your project
  ///   - authProvider: An instance that will handle the actual authentication duties.
  public init(deploymentUrl: String, authProvider: any AuthProvider<T>) {
    self.authProvider = authProvider
    self.authState = authPublisher.eraseToAnyPublisher()
    super.init(deploymentUrl: deploymentUrl)
    setupTokenRefreshManager()
  }

  init(ffiClient: MobileConvexClientProtocol, authProvider: any AuthProvider<T>) {
    self.authProvider = authProvider
    self.authState = authPublisher.eraseToAnyPublisher()
    super.init(ffiClient: ffiClient)
    setupTokenRefreshManager()
  }

  private func setupTokenRefreshManager() {
    tokenRefreshManager = TokenRefreshManager(
      authProvider: authProvider,
      refreshLeewaySeconds: 60,
      onTokenRefreshed: { [weak self] newToken in
        guard let self = self else { return }
        try await self.ffiClient.setAuth(token: newToken)
      },
      onRefreshFailed: { [weak self] error in
        guard let self = self else { return }
        Task {
          await self.logout()
        }
      }
    )
  }

  /// Triggers a UI driven login flow and updates the ``authState``.
  ///
  /// The ``authState`` is set to ``AuthState.loading`` immediately upon calling this method and
  /// will change to either ``AuthState.authenticated`` or ``AuthState.unauthenticated``
  /// depending on the result.
  public func login() async -> Result<T, Error> {
    await login(strategy: authProvider.login)
  }

  /// Triggers a cached, UI-less re-authentication flow using previously stored credentials and updates the
  /// ``authState``.
  ///
  /// If no credentials were previously stored, or if there is an error reusing stored credentials, the resulting
  /// ``authState`` willl be ``AuthState.unauthenticated``. If supported by the ``AuthProvider``,
  /// a call to ``login()`` should store another set of credentials upon successful authentication.
  ///
  /// The ``authState`` is set to ``AuthState.loading`` immediately upon calling this method and
  /// will change to either ``AuthState.authenticated`` or ``AuthState.unauthenticated``
  /// depending on the result.
  public func loginFromCache() async -> Result<T, Error> {
    await login(strategy: authProvider.loginFromCache)
  }

  /// Triggers a logout flow and updates the ``authState``.
  ///
  /// The ``authState`` will change to ``AuthState.unauthenticated`` if logout is successful.
  public func logout() async {
    tokenRefreshManager?.stopMonitoring()

    do {
      try await authProvider.logout()
      try await ffiClient.setAuth(token: nil)
      authPublisher.send(AuthState.unauthenticated)
    } catch {
      dump(error)
    }
  }

  private func login(strategy: LoginStrategy) async -> Result<T, Error> {
    authPublisher.send(AuthState.loading)
    do {
      let authData = try await strategy()
      try await ffiClient.setAuth(token: authProvider.extractIdToken(from: authData))

      // Start monitoring token expiration for automatic refresh
      tokenRefreshManager?.startMonitoring(authData: authData)

      authPublisher.send(AuthState.authenticated(authData))
      return Result.success(authData)
    } catch {
      dump(error)
      authPublisher.send(AuthState.unauthenticated)
      return Result.failure(error)
    }
  }

  private typealias LoginStrategy = () async throws -> T
}

private class SubscriptionAdapter<T: Decodable>: QuerySubscriber {
  typealias Publisher = PassthroughSubject<T, ClientError>

  let publisher: Publisher

  init(publisher: Publisher) {
    self.publisher = publisher
  }

  func onError(message: String, value: String?) {
    let err: ClientError
    if let value {
      err = ClientError.ConvexError(data: value)
    } else {
      err = ClientError.ServerError(msg: message)
    }
    publisher.send(
      completion: Subscribers.Completion.failure(err))
  }

  func onUpdate(value: String) {
    publisher.send(try! JSONDecoder().decode(Publisher.Output.self, from: Data(value.utf8)))
  }
}

private class WebSocketStateAdapter: WebSocketStateSubscriber {
  private let subject = PassthroughSubject<WebSocketState, Never>()
  
  init() { }

  func onStateChange(state: UniFFI.WebSocketState) {
    subject.send(state)
  }
  
  func newPublisher() -> AnyPublisher<WebSocketState, Never> {
    return subject.eraseToAnyPublisher()
  }
}
