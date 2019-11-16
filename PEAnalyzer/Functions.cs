using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using static PEAnalyzer.WriteString;

namespace PEAnalyzer
{
    public static class Functions
    {


        // ReadDosHeader() :: Анализ dos header
        public static void ReadDosHeader (BinaryReader reader)
        {
            WriteLine("Поле", "Код", "Значение\n");

            Console.WriteLine("--------------------------DOS HEADER---------------------------------------------------------------------------------\n");

            string sign = ReadByte(reader, 2);

            // Проверка сигнатуры MZ

            Structure.DOS_Header dos_header = new Structure.DOS_Header();
            if (dos_header.ValidSignature(sign))
            {

                WriteLine("e_magic", sign, "Файл имеет формат PE");
            }
            else
            {
                throw new Exception("Сигнатура MZ не совпадает. Не является PE-файлом. Программа будет остановлена.");
            }

            // Смещение до PE заголовка

            reader.BaseStream.Seek(60, SeekOrigin.Begin);
            string addrPEstr = ReadByte(reader, 4);
            reader.BaseStream.Seek(Convert.ToInt32(addrPEstr, 16), SeekOrigin.Begin);
            WriteLine("e_lfanew", addrPEstr, "Смещение до PE заголовка");
            Console.WriteLine();
        }

        // ReadPEHeader() :: Анализ pe header
        public static string ReadPEHeader (BinaryReader reader)
        {
            Console.WriteLine("--------------------------PE HEADER----------------------------------------------------------------------------------\n");

            string signature = ReadByte(reader, 4);

            // Проверка сигнатуры PE

            Structure.PE_Header pe_header = new Structure.PE_Header();
            if (pe_header.ValidSignature(signature))
            {
                WriteLine("Signature", signature, "Файл имеет формат PE");
            }
            else
            {
                throw new Exception("Сигнатура PE заголовка не является стандартной. Не является PE-файлом. Программа будет остановлена.");
            }

            // Файловый заголовок

            string machine = ReadByte(reader, 2);
            Structure.FileHeader file_header = new Structure.FileHeader();
            Console.WriteLine();
            Console.WriteLine("      Файловый заголовок:\n");
            WriteLine("Machine", machine, file_header.IsMachine(machine));
            string NumberOfSection = ReadByte(reader, 2);
            WriteLine("NumberOfSections", NumberOfSection, "Количество секций");
            byte[] bytearr = new byte[8];
            reader.Read(bytearr, 0, 4);
            bool flag = false;

            for (int i = 0; i < bytearr.Length; i++)
            {
                if (bytearr[i] != 0) flag = true;
            }
            if (flag)
            {
                long longVar = BitConverter.ToInt64(bytearr, 0);
                DateTime dateTimeValue = new DateTime(1969, 12, 31).AddSeconds(longVar + 57600);
                WriteLine("TimeDateStamp", Convert.ToString(dateTimeValue), "Дата и время создания файла");
            }
            else
            {
                WriteLine("TimeDateStamp", "00000000", "Дата и время создания файла");
            }

            WriteLine("PointerToSymbolTable", ReadByte(reader, 4), "Указатель на таблицу символов");
            WriteLine("NumberOfSymbols", ReadByte(reader, 4), "Число символов таблицы");
            WriteLine("SizeOfOptionalHeader", ReadByte(reader, 2), "Размер опционального заголовка. Для объектного файла равен 0.");
            WriteLine("Characteristics", ReadByte(reader, 2), "Различные информационные флаги; по большому счету, не влияют на процесс загрузки");

            // Опциональный заголовок

            Console.WriteLine();
            Console.WriteLine("      Опциональный заголовок:\n");

            string bit = ReadByte(reader, 2);
            Structure.OptionHeader option_header = new Structure.OptionHeader();
            WriteLine("Magic", bit, option_header.BitIs(bit));
            reader.BaseStream.Seek(14, SeekOrigin.Current);
            WriteLine("AddressOfEntryPoint", ReadByte(reader, 4), "Виртуальный адрес точки входа");

            if (bit == "020b")
            {
                reader.BaseStream.Seek(4, SeekOrigin.Current);
                WriteLine("ImageBase", ReadByte(reader, 4), "Предпочтительный адрес загрузки программы в память. В большистве случаев равен 0x00400000.");
                reader.BaseStream.Seek(4, SeekOrigin.Current);
            }
            else
            {
                reader.BaseStream.Seek(8, SeekOrigin.Current);
                WriteLine("ImageBase", ReadByte(reader, 4), "Предпочтительный адрес загрузки программы в память. В большистве случаев равен 0x00400000.");
            }
            WriteLine("SectionAlignment", ReadByte(reader, 4), "Выравнивание необработанных данных разделов в виртуальной памяти.");
            WriteLine("FileAlignment", ReadByte(reader, 4), "Выравнивание необработанных данных разделов в файле. В десятичной системе счисления значение должно быть степенью 2 между 512 и 64K (включительно)");
            reader.BaseStream.Seek(8, SeekOrigin.Current);

            string maxVer = ReadByte(reader, 2);
            WriteLine("MajorSubsystemVersion ", maxVer, "Основной номер версии требуемой операционной системы. NT " + maxVer[3] + ".");

            string minVer = ReadByte(reader, 2);
            WriteLine("MinorSubsytemVersion ", minVer, "Дополнительный номер версии требуемой операционной системы. Не ниже NT " + minVer[3] + ".");

            reader.BaseStream.Seek(4, SeekOrigin.Current);
            WriteLine("SizeOfImage", ReadByte(reader, 4), "Размер области памяти, необходимый для размещения образа PE-файла.");
            WriteLine("SizeOfHeaders", ReadByte(reader, 4), "Размер заголовков файла в памяти");
            reader.BaseStream.Seek(4, SeekOrigin.Current);

            string sub = ReadByte(reader, 2);
            WriteLine("Subsystem", sub, "Тип подсистемы. " + option_header.SubsystemIs(sub));

            if (bit == "020b")
            {
                reader.BaseStream.Seek(38, SeekOrigin.Current);
            }
            else
            {
                reader.BaseStream.Seek(22, SeekOrigin.Current);
            }
            WriteLine("NumberOfRvaAndSizes", ReadByte(reader, 4), "Число каталогов в массиве каталогов. По умолчанию равно 16.");


            // Каталоги данных

            Console.WriteLine();
            Console.WriteLine("      Директория данных:\n");

            WriteLine("", ReadByte(reader, 4), "Относительный виртуальный адрес каталога экспорта");
            WriteLine("", ReadByte(reader, 4), "Размер каталога экспорта");
            WriteLine("", ReadByte(reader, 4), "Относительный виртуальный адрес каталога импорта");
            WriteLine("", ReadByte(reader, 4), "Размер каталога импорта");
            reader.BaseStream.Seek(112, SeekOrigin.Current);

            Console.WriteLine();
            return NumberOfSection;
        }

        // ReadSectionHeader() :: Анализ pe header
        public static void ReadSectionHeader (BinaryReader reader, string numberOfSection)
        {
            Console.WriteLine("--------------------------SECTION HEADER----------------------------------------------------------------------------------\n");

            int NumberSection = Convert.ToInt32(numberOfSection, 16);
            for (int i = 0; i < NumberSection; i++)
            {
                Structure.SectionHeader section_header = new Structure.SectionHeader();
                byte[] bytearr = new byte[16];
                reader.Read(bytearr, 0, 8);
                string name = Encoding.ASCII.GetString(bytearr, 0, 8);
                Const constName = new Const();
                WriteLine("Name", name, "Название секции. " + constName.IsStandartSection(name));
                WriteLine("VirtualSize", ReadByte(reader, 4), "Размер секции в виртуальной памяти");
                WriteLine("VirtualAddress", ReadByte(reader, 4), "Относительный адрес секции в виртуальной памяти");
                WriteLine("SizeOfRawData", ReadByte(reader, 4), "Размер секции в файле");
                WriteLine("PointerToRawData", ReadByte(reader, 4), "Указатель на данные");
                WriteLine("PointerToRelocations", ReadByte(reader, 4), "Указатель файла на начало записи перемещения для раздела. В исполняемых файлах равно 0.");
                WriteLine("PointerToLinenumbers", ReadByte(reader, 4), "Указатель файла на начало записи номера строки для раздела. В исполняемых файлах равно 0.");
                WriteLine("NumberOfRelocations", ReadByte(reader, 2), "Количество записей перемещения для раздела. В исполняемых файлах равно 0.");
                WriteLine("NumberOfLinenumbers", ReadByte(reader, 2), "Количество строк-номеров записей для раздела. В исполняемых файлах равно 0.");

                string character = ReadByte(reader, 4);
                WriteLine("Characteristics", character, section_header.GetCharacteristics(character));

                Console.WriteLine();
            }
        }
    }
}
