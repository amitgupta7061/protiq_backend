import {
    Controller,
    Get,
    Patch,
    Param,
    Body,
    Query,
    UseGuards,
    ParseIntPipe,
    DefaultValuePipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';

@ApiTags('Users')
@ApiBearerAuth()
@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get('profile')
    @ApiOperation({ summary: 'Get current user profile' })
    async getProfile(@CurrentUser('id') userId: string) {
        return this.userService.getProfile(userId);
    }

    @Patch('profile')
    @ApiOperation({ summary: 'Update current user profile' })
    async updateProfile(
        @CurrentUser('id') userId: string,
        @Body() dto: UpdateUserDto,
    ) {
        return this.userService.updateProfile(userId, dto);
    }

    @Get()
    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @ApiOperation({ summary: 'Get all users (Admin only)' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getAllUsers(
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    ) {
        return this.userService.getAllUsers(page, limit);
    }

    @Patch(':id/deactivate')
    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @ApiOperation({ summary: 'Deactivate a user (Admin only)' })
    async deactivateUser(
        @Param('id') userId: string,
        @CurrentUser('id') adminId: string,
    ) {
        return this.userService.deactivateUser(userId, adminId);
    }
}
