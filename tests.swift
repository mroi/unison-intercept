import XCTest

// satisfy the method swizzling in the intercept constructor
@objc(MyController) class UnisonSurrogate: NSObject {
	@objc(connect:) func reset(_ profile: NSString = "") {}
}

class Tests: XCTestCase {
}
