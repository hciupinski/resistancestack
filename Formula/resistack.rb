class Resistack < Formula
  desc "Baseline security platform for VPS hosts and CI pipelines"
  homepage "https://github.com/hciupinski/resistancestack"
  license "MIT"

  url "https://github.com/hciupinski/resistancestack.git", branch: "main"
  version "0.1.1"
  head "https://github.com/hciupinski/resistancestack.git", branch: "main"

  depends_on "go" => :build

  livecheck do
    skip "Development formula tracks the main branch until versioned releases are published"
  end

  def install
    system "go", "build", *std_go_args, "./cmd/resistack"
  end

  test do
    output = shell_output("#{bin}/resistack --help")
    assert_match "ResistanceStack", output
    assert_match "inventory", output
    ci_output = shell_output("#{bin}/resistack ci --help")
    assert_match "generate", ci_output
  end
end
