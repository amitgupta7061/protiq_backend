import { IsNotEmpty, IsObject } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SubmitAttemptDto {
    @ApiProperty({
        example: {
            'q1-uuid': 'Paris',
            'q2-uuid': 'JavaScript',
        },
        description: 'Map of questionId to selected answer',
    })
    @IsObject()
    @IsNotEmpty()
    answers: Record<string, string>;
}
