import XCTest

// satisfy the method swizzling in the intercept constructor
@objc(MyController) class UnisonSurrogate: NSObject {
	@objc(connect:) dynamic func reset(_ profile: NSString = "") {}
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

	private func loadProfile(_ profile: String) {
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

		// pass root directory to config
		if config.root.0.string == .none {
			Tests.root.withUnsafeFileSystemRepresentation {
				let length = strlen($0!)
				let root = UnsafeMutablePointer<CChar>.allocate(capacity: length + 1)
				root.assign(from: $0!, count: length + 1)
				config.root.0 = string_s(string: root, length: length)
			}
		}
	}

	private func touch(_ file: URL) {
		_ = file.withUnsafeFileSystemRepresentation {
			close(interceptOpen($0!, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR))
		}
	}

	private func unlink(_ file: URL) {
		_ = file.withUnsafeFileSystemRepresentation {
			Darwin.unlink($0!)
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


// MARK: - Test Functions

extension Tests {

	func testConfig() {
		loadProfile("""
			root     = /fcChXfYky
			root     = /ZIopXJKWq
			#precmd  = tIGEmizPts
			#postcmd = JgEPTRILIb
			#post    = Path FUHP/kwuwu -> 3RXO7ZAC5w
			#post    = Path A/eiVQBcyU -> 7RqAcYFY0d
			#symlink = Path aTp9W/HNyp -> CPYYlSAK3G
			#symlink = Path Qz/UR -> IZMryE2y93
			""")
		XCTAssert(String(cString: config.root.0.string) == "/fcChXfYky")
		XCTAssert(String(cString: config.root.1.string) == "/ZIopXJKWq")
		XCTAssert(String(cString: config.pre_command) == "tIGEmizPts")
		XCTAssert(String(cString: config.post_command) == "JgEPTRILIb")
		XCTAssert(String(cString: config.post.pointee.pattern.string) == "FUHP/kwuwu")
		XCTAssert(String(cString: config.post.pointee.command) == "3RXO7ZAC5w")
		XCTAssert(String(cString: config.post.pointee.next.pointee.pattern.string) == "A/eiVQBcyU")
		XCTAssert(String(cString: config.post.pointee.next.pointee.command) == "7RqAcYFY0d")
		XCTAssert(String(cString: config.symlink.pointee.path.string) == "Qz/UR")
		XCTAssert(String(cString: config.symlink.pointee.target) == "IZMryE2y93")
		XCTAssert(String(cString: config.symlink.pointee.next.pointee.path.string) == "aTp9W/HNyp")
		XCTAssert(String(cString: config.symlink.pointee.next.pointee.target) == "CPYYlSAK3G")
	}

	func testPrePost() {
		loadProfile("""
			#precmd  = run 1
			#post    = Path trigger -> run 2
			#post    = Path trigger -> run 3
			#postcmd = run 4
			""")
		let command = "#!/bin/sh\nprintf $1 >> $UNISON/trace\n"
		let commandFile = Tests.root.appendingPathComponent(".unison/run")
		let archiveFile = Tests.root.appendingPathComponent(".unison/ar00000000000000000000000000000000")
		let traceFile = Tests.root.appendingPathComponent(".unison/trace")
		let triggerFile = Tests.root.appendingPathComponent("trigger")

		// put command script in unison folder
		try! command.write(to: commandFile, atomically: false, encoding: .utf8)
		try! files.setAttributes([.posixPermissions: S_IRWXU], ofItemAtPath: commandFile.path)
		// create archive file to trigger pre command
		touch(archiveFile)
		XCTAssert(try! String(contentsOf: traceFile, encoding: .utf8) == "1")
		// trigger per-file post command
		touch(triggerFile)
		unlink(triggerFile)
		XCTAssert(try! String(contentsOf: traceFile, encoding: .utf8) == "123")
		// unlink archive file to trigger global post command
		unlink(archiveFile)
		XCTAssert(try! String(contentsOf: traceFile, encoding: .utf8) == "1234")
	}
}
