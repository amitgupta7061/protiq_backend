import { IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateCompanyDto {
    @ApiProperty({ example: 'Acme Corp' })
    @IsString()
    @IsNotEmpty()
    name: string;

    @ApiPropertyOptional({ example: 'A software company' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional({ example: 'https://acme.com' })
    @IsUrl()
    @IsOptional()
    website?: string;
}

export class UpdateCompanyDto {
    @ApiPropertyOptional({ example: 'Acme Corp Updated' })
    @IsString()
    @IsOptional()
    name?: string;

    @ApiPropertyOptional({ example: 'Updated description' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional({ example: 'https://acme-updated.com' })
    @IsUrl()
    @IsOptional()
    website?: string;
}
