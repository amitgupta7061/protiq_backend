import { Controller, Get, Delete, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { DeviceService } from './device.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

@ApiTags('Devices')
@ApiBearerAuth()
@Controller('devices')
export class DeviceController {
    constructor(private readonly deviceService: DeviceService) { }

    @Get()
    @ApiOperation({ summary: 'Get all trusted devices for the current user' })
    async getUserDevices(@CurrentUser('id') userId: string) {
        return this.deviceService.getUserDevices(userId);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Revoke a trusted device' })
    async revokeDevice(
        @CurrentUser('id') userId: string,
        @Param('id') deviceId: string,
    ) {
        return this.deviceService.revokeDevice(userId, deviceId);
    }
}
