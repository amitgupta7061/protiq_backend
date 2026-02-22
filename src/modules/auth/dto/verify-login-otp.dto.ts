import { IsEmail, IsNotEmpty, IsOptional, IsString, Length } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class VerifyLoginOtpDto {
    @ApiProperty({ example: 'john@example.com' })
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @ApiProperty({ example: '123456' })
    @IsString()
    @IsNotEmpty()
    @Length(6, 6)
    code: string;

    @ApiPropertyOptional({ example: 'browser-fingerprint-hash-abc123' })
    @IsString()
    @IsOptional()
    deviceFingerprint?: string;

    @ApiPropertyOptional({ example: 'Chrome on Windows' })
    @IsString()
    @IsOptional()
    deviceName?: string;
}
