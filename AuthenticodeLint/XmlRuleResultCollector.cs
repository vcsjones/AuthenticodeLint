using AuthenticodeLint.Rules;
using System.Xml.Linq;

namespace AuthenticodeLint
{
    public class XmlRuleResultCollector : IRuleResultCollector
    {
        private string _path;
        private readonly XDocument _document;
        private XElement _currentSet;

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

        public void CollectResult(IAuthenticodeRule rule, RuleResult result)
        {
            _currentSet.Add(new XElement("check", new XAttribute("ruleId", rule.RuleId), new XAttribute("result", result)));
        }

        public void CompleteSet()
        {
            _document.Root.Add(_currentSet);
            _currentSet = null;
        }

        public void Flush() => _document.Save(_path);
    }
}
