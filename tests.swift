import System
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

		// use POSIX open()/read() so the config intercept layer parses the profile
		let fd = interceptOpen(profileFile.path, FileDescriptor.AccessMode.readOnly.rawValue)
		let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 64, alignment: 1)
		while read(fd, buffer.baseAddress, buffer.count) > 0 {}
		close(fd)

		// pass root directory to config
		if config.root.0.string == .none {
			URL(fileURLWithPath: "/var/empty").withUnsafeFileSystemRepresentation {
				config.root.0 = string_s(string: strdup($0!), length: strlen($0!))
			}
			Tests.root.withUnsafeFileSystemRepresentation {
				config.root.1 = string_s(string: strdup($0!), length: strlen($0!))
			}
		}
	}

	private func traverse(_ path: URL) {
		path.withUnsafeFileSystemRepresentation {
			_ = closedir(opendir($0))
		}
	}

	private func inspect(_ file: URL) {
		file.withUnsafeFileSystemRepresentation {
			let statBuffer = UnsafeMutablePointer<stat>.allocate(capacity: 1)
			defer { statBuffer.deallocate() }
			stat($0!, statBuffer)
		}
	}

	private func touch(_ file: URL) {
		file.withUnsafeFileSystemRepresentation {
			_ = close(interceptOpen($0!, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR))
		}
	}

	private func remove(_ file: URL) {
		file.withUnsafeFileSystemRepresentation {
			_ = unlink($0!)
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
		remove(triggerFile)
		XCTAssert(try! String(contentsOf: traceFile, encoding: .utf8) == "123")
		// remove archive file to trigger global post command
		remove(archiveFile)
		XCTAssert(try! String(contentsOf: traceFile, encoding: .utf8) == "1234")
	}

	func testSymlink() {
		loadProfile("""
			#symlink = Path link -> subdir
			#symlink = Path subdir/subsubdir/link -> notexist
			""")
		let symlink1 = Tests.root.appendingPathComponent("link")
		let subdir = Tests.root.appendingPathComponent("subdir")
		let subsubdir = Tests.root.appendingPathComponent("subdir/subsubdir")
		let symlink2 = Tests.root.appendingPathComponent("subdir/subsubdir/link")

		// trigger creation of first level symlinks/directories
		traverse(Tests.root)
		XCTAssert(try! files.destinationOfSymbolicLink(atPath: symlink1.path) == "subdir")
		XCTAssert(files.fileExists(atPath: subdir.path))
		// trigger creation of second level symlinks/directories
		inspect(subsubdir)
		XCTAssertTrue(files.fileExists(atPath: subsubdir.path))
		XCTAssertFalse(files.fileExists(atPath: symlink2.path))
		// trigger creation of third level symlinks/directories
		traverse(subsubdir)
		XCTAssert(try! files.destinationOfSymbolicLink(atPath: symlink1.path) == "subdir")
		XCTAssertThrowsError(try files.destinationOfSymbolicLink(atPath: symlink2.path))
	}
}
