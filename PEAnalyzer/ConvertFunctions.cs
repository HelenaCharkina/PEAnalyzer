using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PEAnalyzer
{
   // Класс содержит стандартные функции, но реализованные в соответствии с требованиями использования для pe файла
    public static class WriteString
    {
        // Отформатированный вывод данных
        public static void WriteLine(string s1, string s2, string s3)
        {
            Console.Write("      ");
            Console.Write((s1).PadRight(30));
            Console.Write((s2).PadRight(20));
            if (s3.Length > 100)
            {
                int i;
                for (i = 100; i >= 0; i--)
                {
                    if (s3[i] == Convert.ToChar(" ")) break;
                }
                Console.WriteLine(s3.Substring(0, i));
                Console.WriteLine("      " + "".PadRight(50) + s3.Substring(i + 1, s3.Length - 100));

            }
            else Console.WriteLine(s3);
        }

        // Считывает байт из потока и преобразовывает в символ
        public static string ReadByte(BinaryReader reader, int i)
        {
            Stack<string> stack = new Stack<string>();
            string ans = "";
            for (int j = 0; j < i; j++)
            {
                string symbol = Convert.ToString(reader.ReadByte(), 16);
                if (symbol.Length < 2) symbol = "0" + symbol;
                stack.Push(symbol);
            }
            while (stack.Count != 0)
            {
                ans += stack.Pop();
            }
            return ans;
        }

        // Преобразовывает байт в символ
        public static string ConvertByte (byte b)
        {
            string symbol = Convert.ToString(b, 16);
            if (symbol.Length < 2) symbol = "0" + symbol;
            return symbol;
        }

    }
}
