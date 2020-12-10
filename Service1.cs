using System;
using System.ServiceProcess;
using System.Threading;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;

namespace UTL_Service
{
    public partial class Service1 : ServiceBase
    {
        Logger logger;
        public Service1()
        {
            InitializeComponent();
            this.CanStop = true;
            this.CanPauseAndContinue = true;
            this.AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            logger = new Logger();
            Thread loggerThread = new Thread(new ThreadStart(logger.Start));
            loggerThread.Start();
        }

        protected override void OnStop()
        {
            logger.Stop();
            Thread.Sleep(3500);
        }
    }

    class JsonConfig
    {
        public string sourceFolder { get; set; }
        public string targetFolder { get; set; }
        public string archive { get; set; }
        public bool archiveDateOnly { get; set; }
        public bool needToArchive { get; set; }
        public bool needToCompress { get; set; }
        public bool needToEncrypt { get; set; }
        public string cypherKey { get; set; }
    }

    class XMLConfig
    {
        public string sourceFolder { get; set; }
        public string targetFolder { get; set; }
        public string archive { get; set; }
        public bool archiveDateOnly { get; set; }
        public bool needToArchive { get; set; }
        public bool needToCompress { get; set; }
        public bool needToEncrypt { get; set; }
        public string cypherKey { get; set; }
    }

    class Logger
    {
        FileSystemWatcher watcher;
        object obj = new object();
        bool enabled = true;

        string sourceFolder = @"C:\Users\Asus\Desktop\SourceFolder";
        string targetFolder = @"C:\Users\Asus\Desktop\TargetFolder";
        string archive = @"C:\Users\Asus\Desktop\TargetFolder\Archive";
        bool archiveDateOnly = false;
        bool needToArchive = true;
        bool needToCompress = true;
        bool needToEncrypt = true;
        string cypherKey = "key";
        static byte[] encryptingCypher;

        string jsonFilePath = @"C:\Users\Asus\Desktop\config.json";
        string xmlFilePath = @"C:\Users\Asus\Desktop\config.xml";

        public Logger()
        {
            watcher = new FileSystemWatcher(sourceFolder);
            watcher.Created += MainProcess;
        }

        public void Start()
        {
            watcher.EnableRaisingEvents = true;
            while (enabled)
            {
                Thread.Sleep(3500);
            }
        }
        public void Stop()
        {
            watcher.EnableRaisingEvents = false;
            enabled = false;
        }

        private void ManageConfigs()
        {
            if (File.Exists(jsonFilePath))
            {
                dynamic jsonCFG = JsonSerializer.Deserialize<JsonConfig>(File.ReadAllText(jsonFilePath));

                sourceFolder = jsonCFG.sourceFolder;
                targetFolder = jsonCFG.targetFolder;
                archive = jsonCFG.archive;
                archiveDateOnly = jsonCFG.archiveDateOnly;
                needToArchive = jsonCFG.needToArchive;
                needToEncrypt = jsonCFG.needToEncrypt;
                cypherKey = jsonCFG.cypherKey;
            }
            if (File.Exists(xmlFilePath))
            {
                List<XMLConfig> xmlCFGs = new List<XMLConfig>();

                XmlDocument xDoc = new XmlDocument();
                xDoc.Load(xmlFilePath);
                XmlElement xRoot = xDoc.DocumentElement;

                foreach (XmlElement xnode in xRoot)
                {
                    XMLConfig xmlCFG = new XMLConfig();
                    XmlNode attribute = xnode.Attributes.GetNamedItem("CONFIGS");

                    foreach (XmlNode childnode in xnode.ChildNodes)
                    {
                        switch (childnode.Name)
                        {
                            case "sourceFolder": sourceFolder = childnode.InnerText; break;
                            case "targetFolder": targetFolder = childnode.InnerText; break;
                            case "archive": archive = childnode.InnerText; break;
                            case "archiveDateOnly": archiveDateOnly = Boolean.Parse(childnode.InnerText); break;
                            case "needToArchive": needToArchive = Boolean.Parse(childnode.InnerText); break;
                            case "needToCompress": needToCompress = Boolean.Parse(childnode.InnerText); break;
                            case "needToEncrypt": needToEncrypt = Boolean.Parse(childnode.InnerText); break;
                            case "cypherKey": cypherKey = childnode.InnerText; break;
                        }
                    }
                }
            }
        }

        private void MainProcess(object sender, FileSystemEventArgs e)
        {
            ManageConfigs();

            string archiveSubdirectory = $@"{archive}\{SetArchiveName(e.FullPath)}";
            string compressedPath = $@"{targetFolder}\{Path.GetFileNameWithoutExtension(e.FullPath)}.gz";
            string decompressedPath = $@"{archiveSubdirectory}\{Path.GetFileName(e.FullPath)}";

            using (Aes myAes = Aes.Create())
            {
                if (needToArchive && needToEncrypt)
                {
                    DirectoryInfo directory = Directory.CreateDirectory(archiveSubdirectory);

                    EncryptFile(e, myAes);                   
                    CompressFile(e.FullPath, compressedPath);
                    DecompressFile(compressedPath, decompressedPath);
                    DecryptFile(e, myAes);
                    DecryptFile(e, myAes, decompressedPath);             
                }
                if (!needToArchive && needToEncrypt)
                {
                    EncryptFile(e, myAes);
                    CompressFile(e.FullPath, compressedPath);
                    DecryptFile(e, myAes);
                }
                if (needToArchive && !needToEncrypt)
                {
                    DirectoryInfo directory = Directory.CreateDirectory(archiveSubdirectory);

                    CompressFile(e.FullPath, compressedPath);
                    DecompressFile(compressedPath, decompressedPath);
                }
                if (!needToArchive && !needToEncrypt)
                {
                    CompressFile(e.FullPath, compressedPath);
                }
            }
        }
        
        public string SetArchiveName(string filePath)
        {
            string name = File.GetCreationTime(filePath).ToString();

            name = name.Replace(".", "_");
            name = name.Replace(":", "_");
            if (!archiveDateOnly)
                name += " " + Path.GetFileNameWithoutExtension(filePath);

            return name;
        }

        public void CompressFile(string sourceFile, string compressedFile)
        {
            lock (obj)
            {
                using (FileStream sourceStream = new FileStream(sourceFile, FileMode.OpenOrCreate))
                {
                    using (FileStream targetStream = File.Create(compressedFile))
                    {
                        using (GZipStream compressionStream = new GZipStream(targetStream, CompressionMode.Compress))
                        {
                            sourceStream.CopyTo(compressionStream);
                        }
                    }
                }
            }
        }

        public void DecompressFile(string compressedFile, string targetFile)
        {
            lock (obj)
            {
                using (FileStream sourceStream = new FileStream(compressedFile, FileMode.OpenOrCreate))
                {
                    using (FileStream targetStream = File.Create(targetFile))
                    {
                        using (GZipStream decompressionStream = new GZipStream(sourceStream, CompressionMode.Decompress))
                        {
                            decompressionStream.CopyTo(targetStream);
                        }
                    }
                }
            }
        }

        public byte[] EncryptStringToBytes_Aes(string Text, byte[] Key, byte[] IV)
        {
            if (Text == null || Text.Length <= 0)
                throw new ArgumentNullException("The file is empty");

            byte[] encryptedByte;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(Text);
                        }
                        encryptedByte = msEncrypt.ToArray();
                    }
                }
            }
            return encryptedByte;
        }

        public string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string decryptedText = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decryptedText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return decryptedText;
        }

        public void EncryptFile(FileSystemEventArgs e, Aes aes)
        {
            string str;
            using (StreamReader streamReader = new StreamReader(e.FullPath))
            {
                str = streamReader.ReadToEnd();
            }

            encryptingCypher = EncryptStringToBytes_Aes(str, aes.Key, aes.IV);

            using (StreamWriter streamWriter = new StreamWriter(e.FullPath))
            {
                foreach (byte b in encryptingCypher)
                {
                    streamWriter.Write(b);
                }
            }
        }

        public void DecryptFile(FileSystemEventArgs e, Aes aes, string path = null)
        {
            string str;
            if (path == null) path = e.FullPath;
            
            using (StreamWriter streamWriter = new StreamWriter(path))
            {
                str = DecryptStringFromBytes_Aes(encryptingCypher, aes.Key, aes.IV);
                streamWriter.Write(str);
            }
        }

    }
}