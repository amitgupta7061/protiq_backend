import {
    IsString,
    IsNotEmpty,
    IsOptional,
    IsInt,
    IsBoolean,
    IsArray,
    ValidateNested,
    Min,
    ArrayMinSize,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class CreateQuestionDto {
    @ApiProperty({ example: 'What is the capital of France?' })
    @IsString()
    @IsNotEmpty()
    questionText: string;

    @ApiProperty({ example: ['Paris', 'London', 'Berlin', 'Madrid'] })
    @IsArray()
    @ArrayMinSize(2)
    options: string[];

    @ApiProperty({ example: 'Paris' })
    @IsString()
    @IsNotEmpty()
    correctAnswer: string;

    @ApiProperty({ example: 5 })
    @IsInt()
    @Min(1)
    marks: number;
}

export class CreateExamDto {
    @ApiProperty({ example: 'JavaScript Fundamentals' })
    @IsString()
    @IsNotEmpty()
    title: string;

    @ApiPropertyOptional({ example: 'A comprehensive JS exam' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiProperty({ example: 60, description: 'Duration in minutes' })
    @IsInt()
    @Min(1)
    duration: number;

    @ApiProperty({ example: 100 })
    @IsInt()
    @Min(1)
    totalMarks: number;

    @ApiPropertyOptional({ default: false })
    @IsBoolean()
    @IsOptional()
    allowMultipleAttempts?: boolean;
}

export class UpdateExamDto {
    @ApiPropertyOptional({ example: 'Updated Title' })
    @IsString()
    @IsOptional()
    title?: string;

    @ApiPropertyOptional({ example: 'Updated description' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional({ example: 90 })
    @IsInt()
    @Min(1)
    @IsOptional()
    duration?: number;

    @ApiPropertyOptional({ example: 150 })
    @IsInt()
    @Min(1)
    @IsOptional()
    totalMarks?: number;

    @ApiPropertyOptional({ default: false })
    @IsBoolean()
    @IsOptional()
    allowMultipleAttempts?: boolean;
}

export class AddQuestionsDto {
    @ApiProperty({ type: [CreateQuestionDto] })
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreateQuestionDto)
    @ArrayMinSize(1)
    questions: CreateQuestionDto[];
}
