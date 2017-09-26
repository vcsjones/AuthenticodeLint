using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System.Collections.Generic;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class TimestampedRuleTests
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None, null, RuleSet.Modern);

        private static IReadOnlyList<ISignature> GetGraphForFile(string file)
        {
            var extractor = new SignatureExtractor();
            return extractor.Extract(file);
        }

        [
            Theory,
            InlineData("inputs/notimestamp.ex_"),
            InlineData("inputs/notimestamp.dl_")
        ]
        public void ShouldFailIfNoTimestamp(string file)
        {
            var signatures = GetGraphForFile(file);
            var rule = new TimestampedRule();

            var logger = new MemorySignatureLogger();
            var result = rule.Validate(signatures, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature is not timestamped."));
        }

        [Fact]
        public void ShouldFailIfTimestampUsesWeakSignatureAlgorithm()
        {
            var signatures = GetGraphForFile("inputs/timestampedweaksig.ex_");
            var rule = new TimestampedRule();

            var logger = new MemorySignatureLogger();
            var result = rule.Validate(signatures, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature is not timestamped with the expected hash algorithm SHA256."));
        }

        [Fact]
        public void ShouldPassIfTimestampedAlgorithmIsValid()
        {
            var signatures = GetGraphForFile("inputs/timestampedvalid.ex_");
            var rule = new TimestampedRule();

            var logger = new MemorySignatureLogger();
            var result = rule.Validate(signatures, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }
    }
}
