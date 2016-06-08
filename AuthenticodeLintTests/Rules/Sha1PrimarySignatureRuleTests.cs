using AuthenticodeLint;
using AuthenticodeLint.Rules;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace AuthenticodeLintTests.Rules
{
    public class Sha1PrimarySignatureRuleTests
    {
        private static CheckConfiguration Configuration => new CheckConfiguration(new List<string>(), null, false, new HashSet<int>(), false, RevocationChecking.None, null);

        [
            Theory,
            InlineData(KnownOids.MD2),
            InlineData(KnownOids.MD5),
            InlineData(KnownOids.SHA256),
            InlineData(KnownOids.SHA384),
            InlineData(KnownOids.SHA512),
        ]
        public void ShouldFailOnNonSha1Algorithms(string oid)
        {
            var algorithm = new Oid(oid);
            var signature = new FakeSignature
            {
                DigestAlgorithm = algorithm
            };
            var check = new Sha1PrimarySignatureRule();
            var logger = new MemorySignatureLogger();
            var result = check.Validate(new List<ISignature> { signature }, logger, Configuration);
            Assert.Equal(RuleResult.Fail, result);
            Assert.Contains($"Signature 000102030405060708090a: Expected {nameof(KnownOids.SHA1)} digest algorithm but is {algorithm.FriendlyName}.", logger.Messages);
        }

        [Fact]
        public void ShouldPassOnSha1Algorithm()
        {
            var algorithm = new Oid(KnownOids.SHA1);
            var signature = new FakeSignature
            {
                DigestAlgorithm = algorithm
            };
            var check = new Sha1PrimarySignatureRule();
            var logger = new MemorySignatureLogger();
            var result = check.Validate(new List<ISignature> { signature }, logger, Configuration);
            Assert.Equal(RuleResult.Pass, result);
            Assert.Empty(logger.Messages);
        }
    }
}
