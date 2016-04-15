using AuthenticodeLint.PE;
using Xunit;

namespace AuthenticodeLintTests
{
    public class PortableExecutableTests
    {
        [Fact]
        public void ShouldOpenMemoryMappedFile()
        {
            using (var file = new PortableExecutable(@"C:\Windows\notepad.exe"))
            {
                var dosHeader = file.GetDosHeader();
                var peHeader = file.GetPEHeader(dosHeader);
                var dataSection = peHeader.Sections[".data"];
                file.ResolveDataDirectories(dosHeader);
            }

        }
    }
}
