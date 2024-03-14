import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;

public class disasm {

    public static HashMap<Integer, String> opcodes = new HashMap<>();
    public static ArrayList<String> allInstructions = new ArrayList<>();
    public static int instructionLine = 1;

    public static void main(String[] args) {
        // if (args.length != 1) {
        //     System.err.println("Usage: java Disassembler <binary_file>");
        //     System.exit(1);
        
        String fileName = args[0];
        fillOpcodes();
        try (FileInputStream fileInputStream = new FileInputStream(fileName)) {
            byte[] bytes = new byte[4];
            while (fileInputStream.read(bytes) != -1) {
                // Process each 32-bit instruction
                int instruction = bytesToInteger(bytes);
                disassemble(instruction);
            }
            for(int i = 0; i < allInstructions.size(); i++)
            {
                System.out.println(allInstructions.get(i));
            }
            

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int bytesToInteger(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
    }

    private static void disassemble(int instruction) {
        // Disassembly logic goes here
        // Implement the decoding of each instruction type
        String rm = "";
        String shamt = "";
        String rn = "";
        String rd = "";
        String aluImmediate = "";
        String dtAddress = "";
        String rt = "";
        String type = "";
        String mnemonic = "";
        String instructionText = "";
        String condBrAddress = "";
        String brAddress = "";
        int cond = 0;

        for (int i = 26; i > 20; i--)
        {
            int opcode = instruction >>> i;
            if (opcodes.containsKey(opcode)) 
            {
                String[] parts = opcodes.get(opcode).split(" ");
                type = parts[0];
                mnemonic = parts[1];
                break;
            }
        }

        if ("BR".equals(mnemonic))
        {
            rn = "X" + ((instruction >> 5) & 0b11111);
            allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rn);
        }
        else if("PRNT".equals(mnemonic))
        {
            rd = "X" + (instruction & 0b11111);
            allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rd);
        }
        else if("HALT".equals(mnemonic) || "PRNL".equals(mnemonic) || "DUMP".equals(mnemonic))
        {
            allInstructions.add("Label " + instructionLine + "\n" + mnemonic);
        }
        else if ("LSR".equals(mnemonic) || "LSL".equals(mnemonic))
        {
            shamt = "#" + ((instruction >> 10) & 0b111111);
            rn = "X" + ((instruction >> 5) & 0b11111);
            rd = "X" + (instruction & 0b11111);
            allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rd + ", " + rn + ", " + shamt);
        }
        else if ("B.cond".equals(mnemonic))
        {
            cond = (instruction & 0b11111);
            condBrAddress = "" + ((instruction >> 5) & 0b1111111111111111111);
            int condBrAddressInt = ((instruction >> 5) & 0b1111111111111111111);
            String negativeCondBrAddress = "";
            if((condBrAddressInt & 0b1000000000000000000) == 0b1000000000000000000)
            {
                int condBrAddressIntShift = condBrAddressInt << 13; // shift away the 13 leading zeros
                negativeCondBrAddress = (~(condBrAddressIntShift >> 13)) + 1 + ""; // mask off the non-leading 13 bits, and then convert using 2's complement
                if (cond == 0x0)
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.EQ " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x1) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.NE " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x2) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.HS " + "Label " +(Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x3) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LO " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x4) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.MI " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x5) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.PL " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }   
                else if (cond == 0x6) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.VS " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x7) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.VC " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x8) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.HI " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0x9) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LS " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0xA) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.GE " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0xB) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LT " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0xC) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.GT " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }
                else if (cond == 0xD)
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LE " + "Label " + (Integer.parseInt(negativeCondBrAddress) * -1 + instructionLine));
                }

            }
            else
            {
                if (cond == 0x0)
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.EQ " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x1) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.NE " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x2) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.HS " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x3) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LO " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x4) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.MI " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x5) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.PL " + "Label " + (condBrAddressInt + instructionLine));
                }   
                else if (cond == 0x6) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.VS " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x7) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.VC " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x8) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.HI " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0x9) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LS " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0xA) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.GE " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0xB) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LT " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0xC) 
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.GT " + "Label " + (condBrAddressInt + instructionLine));
                }
                else if (cond == 0xD)
                {
                    allInstructions.add("Label " + instructionLine + "\n" + "B.LE " + "Label " + (condBrAddressInt + instructionLine));
                }
            }
            
        }
        else
        {
            switch (type)
            {
            case "R":
                rm = "X" + ((instruction >> 16) & 0b11111);
                rn = "X" + ((instruction >> 5) & 0b11111);
                rd = "X" + (instruction & 0b11111);
                allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rd + ", " + rn + ", " + rm);
                break;

            case "I":
                aluImmediate = "#" + ((instruction >> 10) & 0b111111111111);
                rn = "X" + ((instruction >> 5) & 0b11111);
                rd = "X" + (instruction & 0b11111);
                allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rd + ", " + rn + ", " + aluImmediate);
                break;

            case "D":
                dtAddress = "#" + ((instruction >> 12) & 0b111111111);
                rn = "X" + ((instruction >> 5) & 0b11111);
                rt = "X" + (instruction & 0b11111);
                allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rt + ", [" + rn + ", " + dtAddress + "]");
                break;

            case "CB":
                condBrAddress = "" + ((instruction >> 5) & 0b1111111111111111111);
                int condBrAddressInt = ((instruction >> 5) & 0b1111111111111111111);
                rt = "X" + (instruction & 0b11111);
                if((condBrAddressInt & 0b1000000000000000000) == 0b1000000000000000000)
                {
                    int condBrAddressIntShift = condBrAddressInt << 13; // shift away the 13 leading zeros
                    String negativeCondBrAddress = (~(condBrAddressIntShift >> 13)) + 1 + ""; // mask off the non-leading 13 bits, and then convert using 2's complement`
                    allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rt + ", Label " + ((Integer.parseInt(negativeCondBrAddress) * -1) + instructionLine));
                }
                else
                {

                    allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " " + rt + ", Label " + (condBrAddressInt + instructionLine));
                }
                break;

            case "B":
                brAddress = "" + (instruction & 0b11111111111111111111111111);
                int brAddressInt = (instruction & 0b11111111111111111111111111);
                if((brAddressInt & 0b10000000000000000000000000) == 0b10000000000000000000000000)
                {
                    int brAddressIntShift = brAddressInt << 6; // shift away the 6 leading zeros
                    String negativeAddress = (~(brAddressIntShift >> 6)) + 1 + ""; // mask off the non-leading 6 bits, and then convert using 2's complement
                    allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " Label " + ((Integer.parseInt(negativeAddress) * -1) + instructionLine));
                }
                else
                {
                    allInstructions.add("Label " + instructionLine + "\n" + mnemonic + " Label " + (brAddressInt + instructionLine));
                }
                break;

            }
        }
        instructionLine++;
    }

    private static HashMap<Integer, String> fillOpcodes(){
        opcodes.put(0b10001011000, "R ADD"); // done
        opcodes.put(0b11101011000, "R SUBS"); // done
        opcodes.put(0b10011011000, "R MUL"); // done
        opcodes.put(0b11111111101, "R PRNT"); // done
        opcodes.put(0b11111111100, "R PRNL"); // done
        opcodes.put(0b11111111110, "R DUMP"); // done
        opcodes.put(0b11111111111, "R HALT"); // done
        opcodes.put(0b11001011000, "R SUB"); // done
        opcodes.put(0b11010011011, "R LSL"); // done
        opcodes.put(0b11010011010, "R LSR"); // done
        opcodes.put(0b10101010000, "R ORR"); // done
        opcodes.put(0b11001010000, "R EOR"); // done
        opcodes.put(0b10001010000, "R AND"); // done
        opcodes.put(0b11010110000, "R BR"); // done

        opcodes.put(0b1101001000, "I EORI"); // done
        opcodes.put(0b1011001000, "I ORRI"); // done
        opcodes.put(0b1101000100, "I SUBI"); // done
        opcodes.put(0b1111000100, "I SUBIS"); // done
        opcodes.put(0b1001000100, "I ADDI"); // done
        opcodes.put(0b1001001000, "I ANDI"); // done

        opcodes.put(0b101, "B B"); // done
        opcodes.put(0b100101, "B BL"); // done

        opcodes.put(0b01010100, "CB B.cond"); // done
        opcodes.put(0b10110101, "CB CBNZ"); // done
        opcodes.put(0b10110100, "CB CBZ"); // done

        opcodes.put(0b11111000000, "D STUR"); // done
        opcodes.put(0b11111000010, "D LDUR"); // done

        return opcodes;
    }

}