import { BaseEntity, Column, Entity, OneToOne, PrimaryGeneratedColumn, JoinColumn } from 'typeorm';
import { User } from './User';

@Entity('profiles')
export class Profile extends BaseEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column()
    address: string;

    @Column()
    country: string;

    @Column()
    city: string;

    @Column({ nullable: true, type: 'text' })
    postalCode?: string; 

    @Column()
    phoneNumber: string;

    @Column()
    dateOfBirth: Date;

    @OneToOne(() => User, user => user.profile)
    @JoinColumn({ name: 'user' })
    user: User;
}