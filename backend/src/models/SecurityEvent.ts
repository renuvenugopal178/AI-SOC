import mongoose, { Schema, Document, Model } from 'mongoose';

export type SecurityEventSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ISecurityEvent extends Document {
  timestamp: Date;
  source: string;
  eventType: string;
  severity: SecurityEventSeverity;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  username?: string;
  action?: string;
  message?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

const securityEventSchema = new Schema<ISecurityEvent>(
  {
    timestamp: {
      type: Date,
      required: true,
      index: true,
    },
    source: {
      type: String,
      required: true,
      trim: true,
      maxlength: 128,
      index: true,
    },
    eventType: {
      type: String,
      required: true,
      trim: true,
      uppercase: true,
      maxlength: 128,
      index: true,
    },
    severity: {
      type: String,
      required: true,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      default: 'MEDIUM',
      index: true,
    },
    sourceIp: {
      type: String,
      trim: true,
      default: null,
    },
    destinationIp: {
      type: String,
      trim: true,
      default: null,
    },
    sourcePort: {
      type: Number,
      min: 1,
      max: 65535,
      default: null,
    },
    destinationPort: {
      type: Number,
      min: 1,
      max: 65535,
      default: null,
    },
    protocol: {
      type: String,
      trim: true,
      uppercase: true,
      default: null,
    },
    username: {
      type: String,
      trim: true,
      default: null,
      maxlength: 64,
    },
    action: {
      type: String,
      trim: true,
      default: null,
      maxlength: 128,
    },
    message: {
      type: String,
      trim: true,
      default: null,
      maxlength: 4000,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

const SecurityEvent: Model<ISecurityEvent> = mongoose.model<ISecurityEvent>('SecurityEvent', securityEventSchema);

export default SecurityEvent;
