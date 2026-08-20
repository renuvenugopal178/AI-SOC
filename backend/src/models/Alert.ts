import mongoose, { Schema, Document, Model } from 'mongoose';

export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';
export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface IAlert extends Document {
  ruleId: mongoose.Types.ObjectId;
  eventId: mongoose.Types.ObjectId;
  title: string;
  description: string;
  severity: AlertSeverity;
  riskScore: number;
  status: AlertStatus;
  source?: string;
  eventType?: string;
  sourceIp?: string;
  username?: string;
  triggeredAt: Date;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

const alertSchema = new Schema<IAlert>(
  {
    ruleId: {
      type: Schema.Types.ObjectId,
      ref: 'DetectionRule',
      required: true,
      index: true,
    },
    eventId: {
      type: Schema.Types.ObjectId,
      ref: 'SecurityEvent',
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 256,
    },
    description: {
      type: String,
      required: true,
      trim: true,
      maxlength: 2000,
    },
    severity: {
      type: String,
      required: true,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      index: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    status: {
      type: String,
      required: true,
      enum: ['NEW', 'ACKNOWLEDGED', 'RESOLVED'],
      default: 'NEW',
      index: true,
    },
    source: {
      type: String,
      trim: true,
      default: null,
      index: true,
    },
    eventType: {
      type: String,
      trim: true,
      default: null,
      uppercase: true,
      index: true,
    },
    sourceIp: {
      type: String,
      trim: true,
      default: null,
    },
    username: {
      type: String,
      trim: true,
      default: null,
    },
    triggeredAt: {
      type: Date,
      required: true,
      default: Date.now,
      index: true,
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

alertSchema.index({ ruleId: 1, eventId: 1 }, { unique: true });

const Alert: Model<IAlert> = mongoose.model<IAlert>('Alert', alertSchema);

export default Alert;
