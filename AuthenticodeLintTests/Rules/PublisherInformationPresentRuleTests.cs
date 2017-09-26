using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System.Collections.Generic;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class PublisherInformationPresentRuleTests
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None, null, RuleSet.Modern);

        private static IReadOnlyList<ISignature> GetGraphForFile(string file)
        {
            var extractor = new SignatureExtractor();
            return extractor.Extract(file);
        }

        [Fact]
        public void ShouldFailWhenNoPublisherInformation()
        {
            var signature = GetGraphForFile("inputs/pubinfonoexist.ex_");
            var rule = new PublisherInformationPresentRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(signature, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature does not have an accompanying description."), s => s.EndsWith("Signature does not have an accompanying URL."));
        }

        [Fact]
        public void ShouldFailWhenNoPublisherURL()
        {
            var signature = GetGraphForFile("inputs/pubinfohasdescription.ex_");
            var rule = new PublisherInformationPresentRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(signature, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature does not have an accompanying URL."));
        }

        [Fact]
        public void ShouldFailWhenNoPublisherDescription()
        {
            var signature = GetGraphForFile("inputs/pubinfohasurl.ex_");
            var rule = new PublisherInformationPresentRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(signature, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature does not have an accompanying description."));
        }

        [Fact]
        public void ShouldFailWhenUrlIsBogus()
        {
            var signature = GetGraphForFile("inputs/pubinfohasbogusurl.ex_");
            var rule = new PublisherInformationPresentRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(signature, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Collection(logger.Messages, s => s.EndsWith("Signature's accompanying URL is not a valid URI."));
        }


        [Fact]
        public void ShouldPassWhenUrlAndDescriptionPresent()
        {
            var signature = GetGraphForFile("inputs/pubinfovalid.ex_");
            var rule = new PublisherInformationPresentRule();
            var logger = new MemorySignatureLogger();

            var result = rule.Validate(signature, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }
    }
}