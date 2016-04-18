using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System;
using System.Collections.Generic;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class WinCertificatePaddingRuleTests
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None);

        [Fact]
        public void PaddedExecutableShouldFail()
        {
            var file = "../../inputs/wintrustpadded.ex_";
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
            var file = "../../inputs/wintrustnonpadded.ex_";
            var rule = new WinCertificatePaddingRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(file, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }
    }
}
