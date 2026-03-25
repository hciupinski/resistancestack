class Resistack < Formula
  desc "Baseline security platform for VPS hosts and CI pipelines"
  homepage "https://github.com/hciupinski/resistancestack"
  license "MIT"

  head "https://github.com/hciupinski/resistancestack.git", branch: "main"

  depends_on "go" => :build

  livecheck do
    skip "HEAD-only formula until versioned releases are published"
  end

  def install
    system "go", "build", *std_go_args, "./cmd/resistack"
  end

  test do
    output = shell_output("#{bin}/resistack help")
    assert_match "ResistanceStack", output
    assert_match "inventory", output
    assert_match "ci generate", output
  end
end
