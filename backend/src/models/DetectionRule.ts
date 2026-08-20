import mongoose, { Schema, Document, Model } from 'mongoose';

export type DetectionRuleType = 'EVENT_MATCH' | 'THRESHOLD';
export type DetectionRuleSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RuleOperator = 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'STARTS_WITH' | 'GREATER_THAN' | 'LESS_THAN';

export interface IDetectionRule extends Document {
  name: string;
  description?: string;
  ruleType: DetectionRuleType;
  enabled: boolean;
  severity: DetectionRuleSeverity;
  riskScore: number;
  conditions: Record<string, unknown>;
  createdBy?: string;
  createdAt: Date;
  updatedAt: Date;
}

const detectionRuleSchema = new Schema<IDetectionRule>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 128,
    },
    description: {
      type: String,
      trim: true,
      default: null,
      maxlength: 2000,
    },
    ruleType: {
      type: String,
      required: true,
      enum: ['EVENT_MATCH', 'THRESHOLD'],
      index: true,
    },
    enabled: {
      type: Boolean,
      default: true,
      index: true,
    },
    severity: {
      type: String,
      required: true,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      default: 'MEDIUM',
      index: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    conditions: {
      type: Schema.Types.Mixed,
      required: true,
      default: {},
    },
    createdBy: {
      type: String,
      trim: true,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

detectionRuleSchema.index({ name: 1 }, { unique: true });

const DetectionRule: Model<IDetectionRule> = mongoose.model<IDetectionRule>('DetectionRule', detectionRuleSchema);

export default DetectionRule;
