using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class Graph<T>
    {
        public IReadOnlyCollection<GraphItem<T>> Items { get; }

        public Graph(IReadOnlyCollection<GraphItem<T>> items)
        {
            Items = items;
        }

        public static Graph<T> Empty { get; } = new Graph<T>(new List<GraphItem<T>>());

        public IEnumerable<T> VisitAll()
        {
            foreach(var item in Items)
            {
                yield return item.Node;
                foreach(var child in item.Children.VisitAll())
                {
                    yield return child;
                }
            }
        }
    }

    public class GraphItem<T>
    {
        public T Node { get; }
        public Graph<T> Children { get; }

        public GraphItem(T node, Graph<T> children)
        {
            Node = node;
            Children = children;
        }
    }
}
