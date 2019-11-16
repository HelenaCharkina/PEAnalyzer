using System;
using System.Collections.Generic;
using System.Text;

namespace PEAnalyzer
{
    // Класс констант
    public class Const
    {
        // Константы названий секций

        public string[] constSections = new string[] { ".arch" , ".bss" , ".data" , ".edata" , ".idata" , ".pdata" , ".reloc" , ".rsrc" , ".sbss" , ".sdata" , ".srdata" , ".text" , ".xdata" , ".tls"};

        public string IsStandartSection(string name)
        {
            name = name.Substring(0, name.IndexOf("\0"));
            for (int i = 0; i < constSections.Length; i++)
            {
                if (constSections[i] == name)
                {
                    return "Секция имеет стандартное имя!";
                }
            }
            return "Секция имеет не стандартное имя!";
        }
    }
}
