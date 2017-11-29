/************************************************************************************
 *	file: FileTransfer.java
 *	author: Daniel Spencer
 *	class: CS 380 - computer networks
 *
 *	assignment: Project 7
 *	date last modified: 11/27/2017
 *
 *	purpose:
 *
 ************************************************************************************/
import java.io.*;
import java.security.*;
import java.net.*;
import java.nio.file.Files;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.getInstance;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class FileTransfer {
    
    private static SecretKey sKey;
    public static void main(String[] args) throws  Exception {
        if (args[0].equals("makekeys")) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(4096);
                KeyPair key = generator.genKeyPair();
                PrivateKey pKey = key.getPrivate();
                PublicKey publickey = key.getPublic();
                try (ObjectOutputStream oos = new ObjectOutputStream (new FileOutputStream(new File("public.bin")))) {
                    oos.writeObject(publickey);
                }
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                    oos.writeObject(pKey);
                }
            }
            catch (NoSuchAlgorithmException e) {
                System.out.println("error");

            }
        }

        if (args[0].equals("server")) {
            String pKey = args[1];
            int port = Integer.parseInt(args[2]);
            try(ServerSocket serverSocket = new ServerSocket(port)) {
                Socket socket = serverSocket.accept();
                String address = socket.getInetAddress().getHostAddress();
                System.out.printf("Client connected: %s%n", address);
                InputStream is = socket.getInputStream();
                ObjectInputStream ois = new ObjectInputStream(is);
                OutputStream os = socket.getOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(os);
                while (true) {
                    try {
                        StartMessage sm = (StartMessage) ois.readObject();
                        AckMessage am = new AckMessage(0);
                        oos.writeObject(am);
                        Cipher cipher = getInstance("RSA");
                        ObjectInputStream importPrivateKey = new ObjectInputStream(new FileInputStream(pKey));
                        RSAPrivateKey rsa = (RSAPrivateKey) importPrivateKey.readObject();
                        cipher.init(Cipher.UNWRAP_MODE, rsa);
                        sKey = (SecretKey)cipher.unwrap(sm.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
                        int chunkSize = sm.getChunkSize();
                        int fileSize = (int)sm.getSize();
                        int numOfChunks = (int)(Math.ceil((double)fileSize / (double)chunkSize));
                        String fMessage = "";
                        byte[] decChunk;
                        for(int i = 0; i < numOfChunks; i++) {
                            Chunk c = (Chunk)ois.readObject();
                            System.out.println("Chunks received [" + c.getSeq() + "/" + numOfChunks + "].");
                            decChunk = decryptChunk(c.getData(), sKey);
                            int checksum = getChecksum(decChunk);
                            if (checksum == c.getCrc()) {
                                fMessage += new String(decChunk);
                                AckMessage ack = new AckMessage((c.getSeq() + 1));
                                oos.writeObject(ack);
                            }
                            else {
                                System.out.println("error");
                                System.exit(0);
                            }
                        }
                        BufferedWriter out = new BufferedWriter(new FileWriter("test2.txt"));
                        out.write(fMessage);
                        out.close();
                        checkEnd(socket);
                        ois.close();
                        os.close();
                        is.close();
                        ois.close();
                        System.out.println("Transfer Complete.");
                        System.out.println("Output path: test2.txt");

                    }
                    catch (Exception e) {
                        System.out.println("error");
                    }
                }
            }
        }

        if (args[0].equals("client")) {
            String publicKey = args[1];
            String host = args[2];
            int port = Integer.parseInt(args[3]);
            byte[] sessionKey = createSessionKey(publicKey);
            try (Socket socket = new Socket(host, port)) {
                if (socket.isConnected()) {
                    Scanner keyboard = new Scanner(System.in);
                    System.out.println("Successfully connected.");
                    System.out.print("Enter Path: ");
                    String inFile = keyboard.nextLine();
                    File outFile = new File(inFile);
                    long fileSize = 0;
                    int cunkNum = 0;
                    int chunkSize = 0;
                    if(outFile.exists()) {
                        fileSize = outFile.length();
                        System.out.print("Enter chunk size[1024]: ");
                        String chunkStr = keyboard.nextLine();
                        if (chunkStr.length() == 0) {
                            chunkSize = 1024;
                        }
                        else {
                            chunkSize = Integer.parseInt(chunkStr);
                        }
                        cunkNum = (int) Math.ceil(((double)fileSize / (double)chunkSize));
                    }

                    System.out.println("Sending: " + inFile + "\tFile Size: "
                            + fileSize + ".");
                    System.out.println("Sending " + chunkSize + " chunks.");

                    sendFile(outFile, cunkNum, socket, chunkSize, sessionKey);
                    ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                    oos.writeObject(new StopMessage(inFile));
                    System.exit(0);

                }

            }
        }

    }


    
    public static void sendFile(File outputFile, int chunkNum, Socket socket, int chunkSize, byte[] key) throws Exception {
        StartMessage messageInfo = new StartMessage(outputFile.getName(), key, chunkSize);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(messageInfo);
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        AckMessage am = (AckMessage)ois.readObject();
        if (am.getSeq() == 0) {
            System.out.println("Acknowledgement");
        }
        else {
            System.out.println("Acknowledgement Failed");
        }
        byte[] rByte = Files.readAllBytes(outputFile.toPath());
        byte[] normal = new byte[chunkSize];
        byte[] lChunk = new byte[(int)outputFile.length() % chunkSize];
        byte[] encChunk;
        int counter = 0;

        int checksum;
        Chunk c;
        for (int i = 1; i <= chunkNum; i++) {
            int sequence = i;
            if (i == chunkNum && lChunk.length > 0) {
                for (int k = 0; k < ((int)outputFile.length() % chunkSize); k++) {
                    lChunk[k] = rByte[counter];
                    counter++;
                }
                checksum = getChecksum(lChunk);
                encChunk = encryptChunk(lChunk);
            }
            else {
                for (int j = 0; j < chunkSize; j++) {
                    normal[j] = rByte[counter];
                    counter++;
                }
                checksum = getChecksum(normal);
                encChunk = encryptChunk(normal);
            }
            c = new Chunk(sequence, encChunk, checksum);
            oos.writeObject(c);
            System.out.println("Chunks completed [" + c.getSeq() + "/" + chunkNum + "].");
            AckMessage ack = (AckMessage)ois.readObject();

        }
    }
            
 
    public static void checkEnd(Socket socket) {
        try {
            Message stop = new StopMessage("test.txt");
            System.exit(0);
        }
        catch (Exception e) {
            System.out.println("error");
        }
    }
    
    public static byte[] encryptChunk(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sKey);
        byte[] encryptedChunk = cipher.doFinal(data);
        return encryptedChunk;
    }
    
    public static byte[] decryptChunk(byte[] data, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, sKey);
        byte[] decryptedChunk = c.doFinal(data);
        return decryptedChunk;
    }

    public static byte[] createSessionKey(String publicKeyName) throws Exception {
        ObjectInputStream os = new ObjectInputStream(new FileInputStream(publicKeyName));
        RSAPublicKey publicKey = (RSAPublicKey)os.readObject();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        sKey = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] key = cipher.wrap(sKey);
        return key;
    }

    public static int getChecksum(byte[] bytes) {
        int length = bytes.length;
        int index = 0;
        long sum = 0;
        while (length > 1) {
            sum += (((bytes[index]<<8) & 0xFF00) | ((bytes[index + 1]) & 0xFF));
            if ((sum & 0xFFFF0000) > 0){
                sum = sum & 0xFFFF;
                sum += 1;
            }
            index += 2;
            length -= 2;
        }
        if (length > 0) {
            sum += (bytes[index]<<8 & 0xFF00);
            if ((sum & 0xFFFF0000) > 0){
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }
        sum = sum & 0xFFFF;
        return (int)~sum;
    }

    
}
