class Zerokernel < Formula
  desc "Zero-knowledge kernel runtime and autonomous AI agent execution auditor"
  homepage "https://github.com/hardonian/zerokernel"
  url "https://github.com/hardonian/zerokernel/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--bin", "zerokernel"
    bin.install "target/release/zerokernel"
  end

  test do
    system "#{bin}/zerokernel", "doctor"
  end
end

