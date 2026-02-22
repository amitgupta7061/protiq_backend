import {
    Controller,
    Get,
    Post,
    Patch,
    Body,
    Param,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { CompanyService } from './company.service';
import { CreateCompanyDto, UpdateCompanyDto } from './dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';

@ApiTags('Companies')
@ApiBearerAuth()
@Controller('companies')
export class CompanyController {
    constructor(private readonly companyService: CompanyService) { }

    @Post()
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Create company profile' })
    async createCompany(
        @CurrentUser('id') userId: string,
        @Body() dto: CreateCompanyDto,
    ) {
        return this.companyService.createCompany(userId, dto);
    }

    @Patch(':id')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Update company details' })
    async updateCompany(
        @Param('id') companyId: string,
        @CurrentUser('id') userId: string,
        @Body() dto: UpdateCompanyDto,
    ) {
        return this.companyService.updateCompany(companyId, userId, dto);
    }

    @Get('dashboard')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'View company dashboard stats' })
    async getDashboard(@CurrentUser('id') userId: string) {
        return this.companyService.getDashboard(userId);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get company by ID' })
    async getCompanyById(@Param('id') companyId: string) {
        return this.companyService.getCompanyById(companyId);
    }
}
