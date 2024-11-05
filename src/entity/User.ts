import crypto from 'crypto';
import { BaseEntity, Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, BeforeInsert, OneToOne, JoinColumn } from 'typeorm';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { generateOtp } from '../utils/generateOtp';
import { Profile } from './Profile';

export enum Provider {
    EMAIL = 'email/password',
    APPLE = 'apple',
    GOOGLE = 'google',
    FACEBOOK = 'facebook'
}

export type AuthProvider = `${Provider}`;

export enum Role {
    USER = 'user',
    EXPERT = 'expert'
}

export type UserRole = `${Role}`;

@Entity('users')
export class User extends BaseEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ unique: true })
    email: string;

    @Column({ unique: true })
    username: string;

    @Column({ select: false })
    password: string;

    @Column({ type: 'enum', enum: Role, default: Role.EXPERT })
    role: string;

    @Column({ type: 'enum', enum: Provider })
    provider: string;

    @Column({ type: 'boolean', nullable: true, default: false })
    emailVerified: boolean

    @Column({ nullable: true, type: 'text' })
    otp?: string | null;

    @Column({ nullable: true, type: 'timestamp' })
    otpExpire?: Date | null;

    @CreateDateColumn()
    createdAt?: Date;

    @UpdateDateColumn({ nullable: true })
    updatedAt?: string;

    @OneToOne(() => Profile, profile => profile.user)
    @JoinColumn({ name: 'profile' })
    profile: Profile;

    @BeforeInsert()
    async hashPassword (): Promise<void> {
        this.password = await bcrypt.hash(this.password, 10);
    }

    getResetPasswordToken (): string {
        // Generate token
        const otp = generateOtp();

        // Hash token and set to resetPassword token field
        this.otp = crypto.createHash('sha256').update(otp).digest('hex');

        // Set expire
        this.otpExpire = new Date (Date.now() + 10 * 60 * 1000) // 10 minutes
        
        return otp;
    }

    async getSignedJwtToken(): Promise<string> {
        return jwt.sign({ id: this.id }, process.env.JWT_SECRET!, {
            expiresIn: process.env.JWT_EXPIRE
        });
    }

    async matchPassword (enteredPassword: string): Promise<boolean> {
        return await bcrypt.compare(enteredPassword, this.password);
    }
}
