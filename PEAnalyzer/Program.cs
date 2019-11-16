using System;
using System.IO;



namespace PEAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            BinaryReader reader = null;

            // Открытие файла
            try
            {
                reader = BaseFunction.OpenFile();
            }
            catch(Exception err)
            {
                if (err != null)
                {
                    Console.WriteLine("Main. Ошибка открытия файла. Программа будет остановлена.");
                    return;
                }
            }
            Console.WriteLine("Запуск программы прошел успешно!\n");

            // Основная программа
            try
            {
                Functions.ReadDosHeader(reader);
                string numberOfSection = Functions.ReadPEHeader(reader);
                Functions.ReadSectionHeader(reader, numberOfSection);

            }
            catch (Exception err)
            {
                Console.WriteLine(err.Message);
                return;
            }

        }
    }
}
