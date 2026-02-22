import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
    @ApiProperty({ example: 'john@example.com' })
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @ApiProperty({ example: 'StrongP@ss123' })
    @IsString()
    @IsNotEmpty()
    password: string;

    @ApiPropertyOptional({ example: 'browser-fingerprint-hash-abc123' })
    @IsString()
    @IsOptional()
    deviceFingerprint?: string;

    @ApiPropertyOptional({ example: 'Chrome on Windows' })
    @IsString()
    @IsOptional()
    deviceName?: string;
}
