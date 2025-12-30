module Decoder(
	input[1:0] op,
	input[5:0] funct,
	output reg MemtoReg,
	output reg ALUSrc,
	output reg[1:0] ImmSrc,
	output reg[1:0] RegSrc,
	output reg[3:0] ALUOp,
	output reg Svalue
	);
	
	always @(*)
	begin
		case (op)
			2'b00: // Data Processing Type
			begin
				MemtoReg = (funct[4:1] == 4'b1010) ? 1'bx : 1'b0; // CMP
				ALUOp = funct[4:1];
				Svalue = funct[0];
				
				if(funct[5] == 1'b1)
				begin
					ALUSrc = 1'b1;
					ImmSrc = 2'b00;  
					RegSrc = (funct[4:1] == 4'b1101) ? 2'bxx : 2'bx0; // MOV
				end
				else
				begin
					ALUSrc = 1'b0;
					ImmSrc = 2'bxx;
					RegSrc = (funct[4:1] == 4'b1101) ? 2'b0x : 2'b00; // MOV
				end
			end
			
			2'b01: // LDR, STR
			begin
				
				MemtoReg = (funct[0] == 1'b1) ? 1'b1 : 1'bx;
				ALUOp = (funct[3] == 1'b1) ? 4'b0100 : 4'b0010;
				Svalue = 1'b0;
				
				if(funct[5] == 1'b0) // Immediate
				begin
					ALUSrc = 1'b1;
					ImmSrc = 2'b01;
					RegSrc = 2'bx0;
				end
				else // Register
				begin
					ALUSrc = 1'b0;
					ImmSrc = 2'bxx;
					RegSrc = 2'b00;				
				end
			end
			
			2'b10: // Branch Type
			begin
				MemtoReg = 1'b0;
				ALUOp = 4'b0100;
				Svalue = 1'b0;
				ALUSrc = 1'b1;
				ImmSrc = 2'b10;
				RegSrc = 2'bx1;
			end
		endcase
	end
endmodule

module ConditionalLogic(
	input[1:0] op,
	input[5:0] funct,
	input[3:0] cond,
	input Zero,
	output reg PCSrc,
	output reg RegWrite,
	output reg MemWrite
	);
	
	reg condEx;
	
	always @(*)
	begin
		case(cond)
			4'b0000: condEx = (Zero == 1'b1) ? 1'b1 : 1'b0;
			4'b0001: condEx = (Zero == 1'b0) ? 1'b1 : 1'b0;
			4'b1110: condEx = 1'b1;
		endcase
	end
	
	always @(*)
	begin
		case(op)
			2'b00: // Data Processing Type
			begin
				PCSrc = 1'b0;
				MemWrite = 1'b0;
				if(condEx == 1'b1)
					RegWrite = (funct[4:1] == 4'b1010) ? 1'b0 : 1'b1; // CMP
				else
					RegWrite = 1'b0;
			end
			2'b01: // LDR, STR
			begin
				PCSrc = 1'b0;
				if(condEx == 1'b1)
				begin
					MemWrite = ~funct[0];
					RegWrite = funct[0];
				end
				else
				begin
					MemWrite = 1'b0;
					RegWrite = 1'b0;
				end
			end
			2'b10: // Branch
			begin
				MemWrite = 1'b0;
				
				if(condEx == 1'b1)
				begin
					PCSrc = 1'b1;
					RegWrite = (funct[4] == 1'b1) ? 1'b1 : 1'b0; // BL
				end
				else
				begin
					PCSrc = 1'b0;
					RegWrite = 1'b0;
				end
			end
		endcase
	end
endmodule

module ctrlSig(
	input[3:0] NZCV,
	input[3:0] cond,
	input[1:0] op,
	input[5:0] funct,
	output[3:0] ALUOp,
	output[1:0] ImmSrc,
	output[1:0] RegSrc,
	output PCSrc,
	output RegWrite,
	output MemWrite,
	output MemtoReg,
	output ALUSrc,
	output Svalue
	);

	Decoder _decoder(
		.op			(op),
		.funct		(funct),
		.MemtoReg	(MemtoReg),
		.ALUSrc		(ALUSrc),
		.ImmSrc		(ImmSrc),
		.RegSrc		(RegSrc),
		.ALUOp 		(ALUOp),
		.Svalue		(Svalue));
	ConditionalLogic _conditional(
		.op			(op),
		.funct		(funct),
		.cond		(cond),
		.Zero		(NZCV[2]),
		.PCSrc		(PCSrc),
		.RegWrite	(RegWrite),
		.MemWrite	(MemWrite));
endmodule