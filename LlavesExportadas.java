import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LlavesExportadas {
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JTextArea verifyTextArea;
    private JTextArea publicKeyTextArea;
    private JButton signButton;
    private JButton verifyButton;
    private KeyPair keyPair;
    private JTextArea LlaveTEXT;

    public LlavesExportadas() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        Files.write(Paths.get("publicKey.txt"), keyPair.getPublic().getEncoded());
        Files.write(Paths.get("privateKey.txt"), keyPair.getPrivate().getEncoded());

        JFrame frame = new JFrame("Rafa y Jetro");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 700);

        LlaveTEXT = new JTextArea(
                "Llave publica: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        inputTextArea = new JTextArea();
        outputTextArea = new JTextArea();
        verifyTextArea = new JTextArea();
        publicKeyTextArea = new JTextArea();
        signButton = new JButton("Firmar");
        verifyButton = new JButton("Verificar");

        signButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String inputText = inputTextArea.getText();
                    byte[] signature = sign(inputText.getBytes());
                    outputTextArea.setText(Base64.getEncoder().encodeToString(signature));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String inputText = verifyTextArea.getText();
                    byte[] signature = Base64.getDecoder().decode(outputTextArea.getText());

                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyTextArea.getText());
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(spec);

                    boolean isValid = verify(inputText.getBytes(), signature, publicKey);
                    JOptionPane.showMessageDialog(frame, "La firma es " + (isValid ? "válida" : "inválida"));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        frame.setLayout(new GridLayout(7, 1));
        frame.add(new JScrollPane(LlaveTEXT));
        frame.add(new JScrollPane(inputTextArea));
        frame.add(signButton);
        frame.add(new JScrollPane(outputTextArea));
        frame.add(new JScrollPane(verifyTextArea));
        frame.add(new JScrollPane(publicKeyTextArea));
        frame.add(verifyButton);

        frame.setVisible(true);
    }

    private byte[] sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    private boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        new LlavesExportadas();
    }
}
