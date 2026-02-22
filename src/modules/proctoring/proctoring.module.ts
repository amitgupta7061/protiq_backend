import { Module } from '@nestjs/common';
import { ProctoringService } from './proctoring.service';
import { ProctoringController } from './proctoring.controller';

@Module({
    controllers: [ProctoringController],
    providers: [ProctoringService],
    exports: [ProctoringService],
})
export class ProctoringModule { }
