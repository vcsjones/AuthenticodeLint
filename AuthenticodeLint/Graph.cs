using System;
using System.Collections;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class Graph<T> : IReadOnlyList<GraphItem<T>>
    {
        private readonly IReadOnlyList<GraphItem<T>> _items;

        public Graph(IReadOnlyList<GraphItem<T>> items)
        {
            _items = items;
        }

        public static Graph<T> Empty { get; } = new Graph<T>(Array.Empty<GraphItem<T>>());

        public int Count => _items.Count;

        public GraphItem<T> this[int index] => _items[index];

        public IEnumerable<T> VisitAll()
        {
            foreach(var item in this)
            {
                yield return item.Node;
                foreach(var child in item.Children.VisitAll())
                {
                    yield return child;
                }
            }
        }

        public IEnumerator<GraphItem<T>> GetEnumerator() => _items.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable<GraphItem<T>>)this).GetEnumerator();

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
