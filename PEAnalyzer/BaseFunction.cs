using System;
using System.IO;

namespace PEAnalyzer
{
    public static class BaseFunction
    {

        // Открытие файла
        public static BinaryReader OpenFile()
        {
            string berry = @"D:\Mulberries-1.0-pc\Mulberries-1.0-pc\Round the Mulberry Bush.exe";
            string csgo = @"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\csgo.exe";
            string vscode = @"D:\Microsoft VS Code\Code.exe";
            string zip = @"D:\7-Zip\7z.exe";
            string wal = @"D:\Walpurgis no Uta\Walpurgis no Uta\Walpurga.exe";
            string vb = @"D:\Oracle\VirtualBox\VirtualBox.exe";
            string txt = @"D:\мультисим\patents.txt";
            BinaryReader reader = null;
            try
            {
                reader = new BinaryReader(File.Open(berry, FileMode.Open));
            }
            catch(Exception err)
            {
                if (err != null)
                {
                    Console.WriteLine("BaseFunction.OpenFile() :: Error Message: {0}", err.Message);
                    throw;
                }
            }
            return reader;
        }

        // Чтение файла и вывод 
        public static void ReadAndWriteFile(BinaryReader reader)
        {
            string ans = "";
            try
            {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        ans += Convert.ToString(reader.ReadByte(), 16);
                        ans += " ";
                    }
                    ans += "\n";
                }
                Console.WriteLine(ans);
            }
            catch (Exception err)
            {
                Console.WriteLine("BaseFunction.ReadAndWriteFile() :: Error Message: {0}", err.Message);
                throw;
            }          
        }

        // Запись в файл
        public static void CreateLocalFile(BinaryReader reader)
        {
            
        }


    }
}
