using AuthenticodeLint;
using System.Linq;
using Xunit;

namespace AuthenticodeLintTests
{
    public class CommandLineParsingTests
    {
        [
            Theory,
            InlineData("a", new[] { "a" }),
            InlineData("    a", new[] { "    ", "a" }),
            InlineData("    a bc", new[] { "    ", "a", " ", "bc" }),
            InlineData(@"    a bc\""", new[] { "    ", "a", " ", @"bc""" }),
            InlineData(@"   ""hello world!""", new[] { "   ", @"""hello world!""" }),
            InlineData(@"sign -in C:\foo.fdpkg -out ""C:\foo signed.fdpkg""", new[] { "sign", " ", "-in", " ", @"C:\foo.fdpkg", " ", "-out", " ", @"""C:\foo signed.fdpkg""" }),
            InlineData("\"", new[] { @"""" }),
            InlineData("\\\\", new[] { @"\" }),
            InlineData("\\bag\\", new[] { @"\bag\" }),
            InlineData("\"\\bag\\\\\"", new[] { @"""\bag\""" }),
            InlineData("tes\\ t", new[] { "tes t" }),
            InlineData("tes\\\\ t", new[] { @"tes\", " ", "t" })
        ]
        public void ShouldParseSimpleKeyAndValue(string input, string[] expected)
        {
            Assert.Equal(expected, CommandLineParser.LexCommandLine(input).ToArray());
        }
    }
}
