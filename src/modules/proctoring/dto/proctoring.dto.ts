import { IsEnum, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ProctoringEventType } from '@prisma/client';

export class CreateProctoringLogDto {
    @ApiProperty({ example: 'attempt-uuid-here' })
    @IsString()
    attemptId: string;

    @ApiProperty({
        enum: ProctoringEventType,
        example: 'TAB_SWITCH',
    })
    @IsEnum(ProctoringEventType)
    type: ProctoringEventType;

    @ApiPropertyOptional({ example: 'Switched to another browser tab' })
    @IsString()
    @IsOptional()
    details?: string;

    @ApiPropertyOptional({ example: '192.168.1.1' })
    @IsString()
    @IsOptional()
    ipAddress?: string;

    @ApiPropertyOptional({ example: 'fingerprint-hash-abc' })
    @IsString()
    @IsOptional()
    deviceFingerprint?: string;

    @ApiPropertyOptional({
        example: { country: 'IN', city: 'Mumbai', lat: 19.07, lon: 72.87 },
    })
    @IsOptional()
    geoLocation?: Record<string, any>;
}
