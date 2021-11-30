
using AuthenticodeLint.Rules;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace AuthenticodeLint
{
    public class XmlRuleResultCollector : IRuleResultCollector
    {
        private readonly string _path;
        private readonly XDocument _document;
        private XElement? _currentSet;

        public XmlRuleResultCollector(string path)
        {
            _path = path;
            _document = new XDocument();
            _document.Add(new XElement("results"));
        }

        public void BeginSet(string setName)
        {
            _currentSet = new XElement("file", new XAttribute("path", setName));
        }

        public void CollectResult(IAuthenticodeRule rule, RuleResult result, IReadOnlyList<string> additionalOutput)
        {
            if (_currentSet is null)
            {
                throw new InvalidOperationException("A set was not opened first.");
            }

            var additionalOutputElements = additionalOutput.Select(msg => new XElement("message", msg));
            _currentSet.Add(new XElement("check",
                new XAttribute("ruleId", rule.RuleId),
                new XAttribute("result", result),
                new XElement("messages", additionalOutputElements.ToArray())));
        }

        public void CompleteSet()
        {
            _document.Root!.Add(_currentSet);
            _currentSet = null;
        }

        public void Flush() => _document.Save(_path);
    }
}
