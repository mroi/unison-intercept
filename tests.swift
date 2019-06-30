import XCTest

// satisfy the method swizzling in the intercept constructor
@objc(MyController) class UnisonSurrogate: NSObject {
	@objc(connect:) func reset(_ profile: NSString = "") {}
}

let files = FileManager.default


class Tests: XCTestCase {

	private static let root = determineTestRoot()

	private class func determineTestRoot() -> URL {
		let unison = ProcessInfo.processInfo.environment["UNISON"]!
		return URL(fileURLWithPath: unison).deletingLastPathComponent()
	}

	override class func setUp() {
		try! files.createDirectory(at: root, withIntermediateDirectories: true)
	}

	func loadProfile(_ profile: String) {
		// write profile to disk
		let configDir = Tests.root.appendingPathComponent(".unison")
		try! files.createDirectory(at: configDir, withIntermediateDirectories: true)
		let profileFile = configDir.appendingPathComponent("default.prf")
		try! profile.write(to: profileFile, atomically: false, encoding: .utf8)

		// POSIX read() so that the config intercept layer parses the profile
		profileFile.withUnsafeFileSystemRepresentation {
			let fd = interceptOpen($0!, O_RDONLY)
			defer { close(fd) }
			let chunkSize = 64
			let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: chunkSize, alignment: 1)
			var bytesRead: Int
			repeat {
				bytesRead = read(fd, buffer.baseAddress, chunkSize)
			} while bytesRead > 0
		}
	}

	override func tearDown() {
		UnisonSurrogate().reset()
		let content = try! files.contentsOfDirectory(at: Tests.root, includingPropertiesForKeys: [])
		content.forEach { try! files.removeItem(at: $0) }
	}

	override class func tearDown() {
		try! files.removeItem(at: root)
	}
}
