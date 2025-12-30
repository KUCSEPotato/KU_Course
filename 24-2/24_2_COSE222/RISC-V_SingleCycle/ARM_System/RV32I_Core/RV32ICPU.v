`timescale 1ns/1ns

/* WARNING: DO NOT MODIFY THE PREDEFINED NAMES OF THE MODULES AND THE PORTS! */
/* NOTE: YOU CAN ADD NEW MODULES, PORTS, WIRES, AND REGISTERS AS NEEDED! */

//
// RV32I Opcode map = Inst[6:0]
//
`define OP_R			    7'b0110011
`define OP_I_Arith    7'b0010011
`define OP_I_Load     7'b0000011
`define OP_I_JALR     7'b1100111
`define OP_S          7'b0100011 
`define OP_B          7'b1100011
`define OP_U_LUI      7'b0110111
`define OP_U_AUIPC    7'b0010111
`define OP_J_JAL      7'b1101111

//
// Main decoder generates all control signals except alucontrol 
//
module maindec(input  [6:0] opcode,               // opcode
               output       auipc,                // AUIPC
               output       lui,                  // LUI
               output       regwrite,             // register write
               output       alusrc,               // ALU source
               output       memtoreg, memwrite,   // memory to register, memory write
               output       branch,               // branch
               output       jal,                  // JAL
               output       jalr);                // JALR

  reg [8:0] controls;

  assign {auipc, lui, regwrite, alusrc, memtoreg, memwrite, branch, jal, jalr} = controls;

  always @(*)
  begin
    case(opcode)
      `OP_R: 			  controls <= 9'b0010_0000_0; // R-type
      `OP_I_Arith: 	controls <= 9'b001100000;
      `OP_I_Load: 	controls <= 9'b001110000;
      `OP_S: 			  controls <= 9'b0001x1000;
      `OP_B: 			  controls <= 9'b0000x0100;
      `OP_U_LUI: 		controls <= 9'b011100000;
      `OP_U_AUIPC:  controls <= 9'b101100000;
      `OP_J_JAL: 		controls <= 9'b001100110;
		  `OP_I_JALR:  	controls <= 9'b001100101;
      default:    	controls <= 9'bxxxxxxxxx;
    endcase
  end

endmodule

//
// ALU decoder generates ALU control signal (alucontrol)
//

// 4'b0000: result <= sum;    // A + B, A - B
// 4'b0001: result <= a & b;
// 4'b0010: result <= a | b;
// 4'b0011: result <= a ^ b;
// 4'b1000: result <= {31'b0,sltu};
module aludec(input      [6:0] opcode,           // opcode
              input      [6:0] funct7,           // funct7
              input      [2:0] funct3,           // funct3
              output reg [4:0] alucontrol);      // ALU control signal

  always @(*)
    case(opcode)
      `OP_R:   		    // R-type
      begin
        case({funct7,funct3})
        /* Try to complete this together :) */
        10'b0000000_000: alucontrol <= 5'b00000; // addition (add)
        10'b0100000_000: alucontrol <= 5'b10000; // subtraction (sub), MSB가 2의 보수 덧셈 위해 ~ + 1 하는 부분
        10'b0000000_111: alucontrol <= 5'b00001; // and (and)
        10'b0000000_110: alucontrol <= 5'b00010; // or (or)
        10'b0000000_100: alucontrol <= 5'b00011; // xor
        default:         alucontrol <= 5'bxxxxx;
        endcase
      end

      `OP_I_Arith:    // I-type Arithmetic
      begin
        case(funct3)
        /* TODO: Add the ALU control signals for I-type Arithmetic instructions */
        3'b000: alucontrol <= 5'b00000; // addi
        //3'b010: alucontrol <= 5'b01000;// slti
        3'b011: alucontrol <= 5'b01000;// sltiu
        3'b100: alucontrol <= 5'b00011; // xori
        3'b110: alucontrol <= 5'b00010; // ori
        3'b111: alucontrol <= 5'b00001; // andi
        //3'b001: // slli
        //3'b101: // srli, srai
        endcase
      end

      `OP_I_Load: 	  // I-type Load (LW, LH, LB...)
        /*** TODO: Add the ALU control signals for I-type Load instructions ***/
      begin
       alucontrol <= 5'b00000; //add
      end

      `OP_I_JALR:		  // I-type Load (JALR)
        /*** TODO: Add the ALU control signals for I-type JALR instructions ***/
      begin
       alucontrol <= 5'b00000; //add
      end

      `OP_B:   		    // B-type Branch (BEQ, BNE, ...)
        /** TODO: Add the ALU control signals for B-type Branch instructions **/
      begin
       alucontrol <= 5'b10000; //sub
      end

      `OP_S:   		    // S-type Store (SW, SH, SB)
        /** TODO: Add the ALU control signals for S-type Store instructions **/
      begin
       alucontrol <= 5'b00000; //add
      end

      `OP_U_LUI: 		  // U-type (LUI)
        /**** TODO: Add the ALU control signals for U-type LUI instructions ****/
      begin
       alucontrol <= 5'b00000; //add
      end
      
	  `OP_U_AUIPC:
	  begin
		alucontrol <= 5'b00000; //add
	  end
	  
      default:
      	alucontrol <= 5'b00000;
    endcase
    
endmodule


//
// CPU datapath
//
module datapath(input         clk, reset_n, // clock and reset signals
                input  [31:0] inst,       // incoming instruction
                input         auipc,      // AUIPC
                input         lui,        // LUI
                input         regwrite,   // register write
                input         memtoreg,   // memory to register
                input         memwrite,   // memory write
                input         alusrc,     // ALU source
                input  [4:0]  alucontrol, // ALU control signal
                input         branch,     // branch
                input         jal,        // JAL
                input         jalr,       // JALR
                output reg [31:0] pc,     // program counter
                output [31:0] aluout,     // ALU output
                output [31:0] MemWdata,   // data to write to memory
                input  [31:0] MemRdata);  // data read from memory

  wire [4:0]  rs1, rs2, rd;               // register addresses
  wire [2:0]  funct3;                     // funct3
  wire [31:0] rs1_data, rs2_data;         // data read from registers
  reg  [31:0] rd_data;                    // data to write to register
  wire [20:1] jal_imm;                    // JAL immediate
  wire [31:0] se_jal_imm;                 // sign-extended JAL immediate
  wire [12:1] jalr_imm;                   // JALR immediate
  wire [31:0] se_jalr_imm;                // sign-extended JALR immediate
  wire [12:1] br_imm;                     // branch immediate
  wire [31:0] se_br_imm;                  // sign-extended branch immediate
  wire [31:0] se_imm_itype;               // sign-extended I-type immediate
  wire [31:0] se_imm_stype;               // sign-extended S-type immediate
  wire [31:0] auipc_lui_imm;              // AUIPC and LUI immediate
  reg  [31:0] alusrc1;                    // 1st source to ALU
  reg  [31:0] alusrc2;                    // 2nd source to ALU
  wire [31:0] branch_dest, jal_dest, jalr_dest;   // branch, jal, jalr destinations
  wire		  Nflag, Zflag, Cflag, Vflag;           // DO NOT MODIFY THESE PORTS!
  wire		  f3beq, f3bne, f3blt, f3bgeu;          // funct3 for branch
  wire		  beq_taken;                            // branch taken (BEQ)
  wire		  bne_taken;                            // branch taken (BNE)
  wire 		  bgeu_taken;                           // branch taken (BGEU)
  wire		  blt_taken;                            // branch taken (BLT)

  assign beq_taken  =  branch & f3beq & Zflag;
  assign bne_taken  =  branch & f3bne & ~Zflag;
  assign blt_taken  =  branch & f3blt & (Nflag != Vflag);
  assign bgeu_taken =  branch & f3bgeu & Cflag;

  assign branch_dest = (pc + se_br_imm);
  assign jal_dest 	 = (pc + se_jal_imm);
  assign jalr_dest   = rs1_data + se_jalr_imm;

  assign MemWdata = rs2_data;

  // JAL immediate
  assign jal_imm[20:1] = {inst[31],inst[19:12],inst[20],inst[30:21]};
  assign se_jal_imm[31:0] = {{11{jal_imm[20]}},jal_imm[20:1],1'b0};
  
  // JALR immediate
  assign jalr_imm[12:1] = {inst[31:20]};
  assign se_jalr_imm[31:0] = {{19{jalr_imm[12]}},jalr_imm[12:1],1'b0};

  // Branch immediate
  assign br_imm[12:1] = {inst[31],inst[7],inst[30:25],inst[11:8]};
  assign se_br_imm[31:0] = {{19{br_imm[12]}},br_imm[12:1],1'b0};

	assign se_imm_itype[31:0] = {{20{inst[31]}},inst[31:20]};
	assign se_imm_stype[31:0] = {{20{inst[31]}},inst[31:25],inst[11:7]};
	assign auipc_lui_imm[31:0] = {inst[31:12],12'b0};

  /* ------------------------------------------------------------------------ */

  assign rs1 = inst[19:15];   // register rs1
  assign rs2 = inst[24:20];                                     /************ TODO: Add the register rs2 assignment ************/
  assign rd  = inst[11:7];                                      /************ TODO: Add the register rd assignment *************/
  assign funct3  = inst[14:12];                                 /************* TODO: Add the funct3 assignment *************/

  //
  // PC (Program Counter) logic 
  //
  assign f3beq  = (funct3 == 3'b000); // BEQ
  assign f3bne  = (funct3 == 3'b001);                                                 /*************** TODO: Add the funct3 for BNE ***************/
  assign f3blt  = (funct3 == 3'b100);                                                 /*************** TODO: Add the funct3 for BLT ***************/
  assign f3bgeu = (funct3 == 3'b111);                                                 /*************** TODO: Add the funct3 for BGEU **************/

  // Program Counter (PC) logic
  always @(negedge clk, negedge reset_n)
  begin
    if (!reset_n)
      pc <= 0;                                                                /********** TODO: Add the reset logic for the program counter **********/
	  else
	  begin
	    if (beq_taken | bne_taken | blt_taken | bgeu_taken)   // branch_taken
			  pc <= branch_dest;
		  else if (jal)         // jal
				pc <= jal_dest;
			else if (jalr)        // jalr
				pc <= jalr_dest;
		  else 
				pc <= pc + 4;                                                           /************ TODO: Add the logic for the program counter ************/
	  end
  end

	// 1st source to ALU (alusrc1)
	always@(*)
	begin
		if      (auipc)	  alusrc1[31:0]  =  pc;
		else if (lui) 		alusrc1[31:0]  =  32'd0;                                                    /************************* TODO *************************/  //x[rd] = sext(immediate[31:12] << 12)
		else          		alusrc1[31:0]  =  rs1_data;                                                   /************************* TODO *************************/ //regitser rs1
	end
	
	// 2nd source to ALU (alusrc2)
	always@(*)
	begin
		if	    (auipc | lui)			  alusrc2[31:0] = auipc_lui_imm[31:0];
		else if (alusrc & memwrite)	alusrc2[31:0] = {{20{inst[31]}},inst[31:25],inst[11:7]};     /******************** TODO ********************/    //store
		else if (alusrc)					  alusrc2[31:0] = {{20{inst[31]}},inst[31:20]};                /******************** TODO ********************/    //imm.
		else									      alusrc2[31:0] = rs2_data;                                  /******************** TODO ********************/    //read data 2
	end

	// Data selection for writing to RF
	always@(*)
	begin
		if	    (jal | jalr)  rd_data[31:0] = pc + 4;
		else if (memtoreg)	  rd_data[31:0] = MemRdata;                       /*********************** TODO ***********************/  //memory data
		else						      rd_data[31:0] = aluout;                         /*********************** TODO ***********************/  //alu result
	end

  /* WARNING: DO NOT MODIFY THE CODE BELOW!!! */
  regfile i_regfile(
    .clk			(clk),
    .we			  (regwrite),
    .rs1			(rs1),
    .rs2			(rs2),
    .rd			  (rd),
    .rd_data	(rd_data),
    .rs1_data	(rs1_data),
    .rs2_data	(rs2_data));

	alu i_alu(
		.a			  (alusrc1),
		.b			  (alusrc2),
		.alucont	(alucontrol),
		.result	  (aluout),
		.N			  (Nflag),
		.Z			  (Zflag),
		.C			  (Cflag),
		.V			  (Vflag));

endmodule

/************** WARNING: DO NOT MODIFY THE CODE BELOW!!! **************/
/************** WARNING: DO NOT MODIFY THE CODE BELOW!!! **************/
/************** WARNING: DO NOT MODIFY THE CODE BELOW!!! **************/
module RV32I (
		      input         clk, reset_n, // clock and reset signals
          output [31:0] pc,		  		// program counter for instruction fetch
          input  [31:0] inst, 			// incoming instruction
          output [3:0] 	be,         // DO NOT MODIFY THIS PORT!
          output        Memwrite, 	// 'memory write' control signal
          output 				Memread,    // 'memory read' control signal
          output [31:0] Memaddr,  	// memory address 
          output [31:0] MemWdata, 	// data to write to memory
          input  [31:0] MemRdata); 	// data read from memory

  wire        auipc, lui;
  wire        alusrc, regwrite;
  wire [4:0]  alucontrol;
  wire        memtoreg, memwrite;
  wire        branch, jal, jalr;

  assign Memwrite = memwrite;
  assign Memread = ~memwrite;
  assign be = 4'b1111;
 

  // Instantiate Controller
  controller i_controller(
    .opcode		(inst[6:0]), 
		.funct7		(inst[31:25]), 
		.funct3		(inst[14:12]), 
		.auipc		(auipc),
		.lui			(lui),
		.memtoreg	(memtoreg),
		.memwrite	(memwrite),
		.branch		(branch),
		.alusrc		(alusrc),
		.regwrite	(regwrite),
		.jal			(jal),
		.jalr			(jalr),
		.alucontrol	(alucontrol));

  // Instantiate Datapath
  datapath i_datapath(
		.clk				(clk),
		.reset_n		(reset_n),
		.auipc			(auipc),
		.lui				(lui),
		.memtoreg		(memtoreg),
		.memwrite		(memwrite),
		.branch			(branch),
		.alusrc			(alusrc),
		.regwrite		(regwrite),
		.jal				(jal),
		.jalr				(jalr),
		.alucontrol		(alucontrol),
		.pc				(pc),
		.inst				(inst),
		.aluout			(Memaddr), 
		.MemWdata		(MemWdata),
		.MemRdata		(MemRdata));

endmodule

//
// Instruction Decoder 
// to generate control signals for datapath
//
module controller(input  [6:0] opcode,
                  input  [6:0] funct7,
                  input  [2:0] funct3,
                  output       auipc,
                  output       lui,
                  output       alusrc,
                  output [4:0] alucontrol,
                  output       branch,
                  output       jal,
                  output       jalr,
                  output       memtoreg,
                  output       memwrite,
                  output       regwrite);

	maindec i_maindec(
		.opcode		(opcode),
		.auipc		(auipc),
		.lui			(lui),
		.memtoreg	(memtoreg),
		.memwrite	(memwrite),
		.branch		(branch),
		.alusrc		(alusrc),
		.regwrite	(regwrite),
		.jal			(jal),
		.jalr			(jalr));

	aludec i_aludec( 
		.opcode     (opcode),
		.funct7     (funct7),
		.funct3     (funct3),
		.alucontrol (alucontrol));

endmodule