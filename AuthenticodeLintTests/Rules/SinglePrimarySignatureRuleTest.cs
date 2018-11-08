using AuthenticodeExaminer;
using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class SinglePrimarySignatureRuleTest
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None, null, RuleSet.Compat);

        [Fact]
        public void ShouldFailOnMultiplePrimarySignatures()
        {
            var signature1 = new FakeSignature
            {
                DigestAlgorithm = new Oid(KnownOids.SHA1)
            };
            var signature2 = new FakeSignature
            {
                DigestAlgorithm = new Oid(KnownOids.SHA256)
            };
            var check = new SinglePrimarySignatureRule();
            var logger = new MemorySignatureLogger();
            var result = check.Validate(new List<ICmsSignature> { signature1, signature2 }, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Contains("Multiple primary signatures exist.", logger.Messages);

        }
    }
}
