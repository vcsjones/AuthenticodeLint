using AuthenticodeExaminer;
using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System;
using System.Collections.Generic;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class WinCertificatePaddingRuleTests
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None, null, RuleSet.Modern);

        [Fact]
        public void PaddedExecutableShouldFail()
        {
            var file = "inputs/wintrustpadded.ex_";
            var rule = new WinCertificatePaddingRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(file, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            var expectedPadding = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("fail"));
            Assert.Contains($"Non-zero data found after PKCS#7 structure: {expectedPadding}.", logger.Messages);
        }

        [Fact]
        public void NonPaddedExecutableShouldPass()
        {
            var file = "inputs/wintrustnonpadded.ex_";
            var rule = new WinCertificatePaddingRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(file, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }
        [Fact]
        public void PaddedLibraryShouldFail()
        {
            var file = "inputs/wintrustpadded.dl_";
            var rule = new WinCertificatePaddingRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(file, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            var expectedPadding = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("fail"));
            Assert.Contains($"Non-zero data found after PKCS#7 structure: {expectedPadding}.", logger.Messages);
        }

        [Fact]
        public void NonPaddedLibraryShouldPass()
        {
            var file = "inputs/wintrustnonpadded.dl_";
            var rule = new WinCertificatePaddingRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(file, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }

        [Fact]
        public void NonBinaryShouldThrow()
        {
            //Rules shouldn't handle non-signed, non-binary content since that validation happens further up.
            var file = "inputs/nonbinary.txt";
            var rule = new WinCertificatePaddingRule();

            Assert.Throws<InvalidOperationException>(() => rule.Validate(file, SignatureLogger.Null, Configuration));
        }
    }
}
