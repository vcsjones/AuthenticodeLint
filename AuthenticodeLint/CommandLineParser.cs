using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthenticodeLint
{

    public struct CommandLineParameter
    {
        private string _name, _value;

        public CommandLineParameter(string name, string value)
        {
            _name = name;
            _value = value;
        }

        public string Name => _name;
        public string Value => _value;
    }


    public class CommandLineParser
    {
        public static IEnumerable<CommandLineParameter> CreateCommandLineParametersWithValues(IEnumerable<string> input)
        {
            string parameterName = null;
            foreach (var token in input)
            {
                if (string.IsNullOrWhiteSpace(token) || token.Length == 0)
                {
                    continue;
                }
                if (parameterName == null)
                {
                    if (token.Length < 2 || token[0] != '-')
                    {
                        throw new InvalidOperationException("Exepecting a named parameter.");
                    }
                    parameterName = token.Substring(1);
                }
                //A named parameter immediate after a named one. Pop the existing named one off.
                else if (token.Length >= 2 && token[0] == '-')
                {
                    yield return new CommandLineParameter(parameterName.ToLowerInvariant(), null);
                    parameterName = token.Substring(1);
                }
                else
                {
                    yield return new CommandLineParameter(parameterName.ToLowerInvariant(), token);
                    parameterName = null;
                }
            }
            if (parameterName != null)
            {
                yield return new CommandLineParameter(parameterName.ToLowerInvariant(), null);
            }
        }

        public static IEnumerable<string> LexCommandLine(string rawInput)
        {
            const char SPACE_TOKEN = ' ', QUOTE_TOKEN = '"', ESCAPE_TOKEN = '\\';
            var currentToken = new List<TokenBit>();
            TokenBit? previousToken = null;
            var quoted = false;
            for (var i = 0; i < rawInput.Length; i++)
            {
                var current = rawInput[i];
                TokenType tokenType;
                if (current == ESCAPE_TOKEN)
                {
                    var canPeek = i + 1 <= rawInput.Length - 1;
                    if (!canPeek)
                    {
                        currentToken.Add(TokenBit.Literal(current, out tokenType));
                    }
                    else
                    {
                        var peek = rawInput[i + 1];
                        if (peek == ESCAPE_TOKEN || peek == QUOTE_TOKEN || peek == SPACE_TOKEN)
                        {
                            i++;
                            currentToken.Add(TokenBit.Literal(peek, out tokenType));
                        }
                        else
                        {
                            currentToken.Add(TokenBit.Literal(current, out tokenType));
                        }
                    }
                }
                else if (current == QUOTE_TOKEN && !quoted && previousToken?.Type == TokenType.Whitespace)
                {
                    quoted = true;
                    yield return BlitTokens(currentToken);
                    currentToken.Clear();
                    currentToken.Add(TokenBit.Whitespace(current, out tokenType));
                }
                else if (current == QUOTE_TOKEN && quoted)
                {
                    quoted = false;
                    currentToken.Add(TokenBit.Literal(current, out tokenType));
                    yield return BlitTokens(currentToken);
                    currentToken.Clear();
                }
                else if (current == SPACE_TOKEN && (currentToken.Count == 0 || previousToken?.Type == TokenType.Whitespace || quoted))
                {
                    currentToken.Add(TokenBit.Whitespace(current, out tokenType));
                }
                else if (current == SPACE_TOKEN && currentToken.Count > 0 && previousToken?.Type != TokenType.Whitespace)
                {
                    yield return BlitTokens(currentToken);
                    currentToken.Clear();
                    currentToken.Add(TokenBit.Whitespace(current, out tokenType));
                }
                else if (current != SPACE_TOKEN && currentToken.Count > 0 && previousToken?.Type == TokenType.Whitespace && !quoted)
                {
                    yield return BlitTokens(currentToken);
                    currentToken.Clear();
                    currentToken.Add(TokenBit.Literal(current, out tokenType));
                }
                else
                {
                    currentToken.Add(TokenBit.Literal(current, out tokenType));
                }
                previousToken = new TokenBit(current, tokenType);
            }
            if (quoted)
            {
                throw new InvalidOperationException("Unexpected end of input with open quote.");
            }
            if (currentToken.Count > 0)
            {
                yield return BlitTokens(currentToken);
            }
        }

        private static string BlitTokens(IEnumerable<TokenBit> bits)
        {
            return new string(bits.Select(c => c.Value).ToArray());
        }

        private struct TokenBit
        {
            public char Value { get; }
            public TokenType Type { get; }

            public TokenBit(char value, TokenType type)
            {
                Value = value;
                Type = type;
            }

            public static TokenBit Whitespace(char value, out TokenType tokenType)
            {
                tokenType = TokenType.Whitespace;
                return new TokenBit(value, tokenType);
            }

            public static TokenBit Literal(char value, out TokenType tokenType)
            {
                tokenType = TokenType.Literal;
                return new TokenBit(value, tokenType);
            }
        }

        private enum TokenType
        {
            Whitespace,
            Literal
        }
    }
}
