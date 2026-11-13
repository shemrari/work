import { AxiosInstance } from 'axios';
import axios from 'axios';

// Create axios instance for Wazuh API
const wazuhApi: AxiosInstance = axios.create({
  baseURL: '/wazuh',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response types based on actual Wazuh API responses
export interface WazuhResponse<T> {
  error: number;
  message: string;
  data: {
    total_affected_items: number;
    affected_items: T[];
    page: {
      limit: number;
      offset: number;
      totalItems: number;
    };
  };
}

export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: string;
  date_add: string;
  os?: {
    name?: string;
    version?: string;
  };
  group?: string[];
}

export interface WazuhAlert {
  id: string;
  rule: {
    id: string;
    level: number;
    description: string;
    groups: string[];
  };
  agent: {
    id: string;
    name: string;
  };
  location: string;
  // Add other fields as needed based on actual API response
  [key: string]: any;
}

// API service functions
export const wazuhService = {
  // Check Wazuh Manager API and Indexer status
  getStatus: async () => {
    try {
      const response = await wazuhApi.get<WazuhResponse<any>>('/status');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch Wazuh status: ${error}`);
    }
  },

  // Get agents from Wazuh Manager API
  getAgents: async (
    limit: number = 50,
    offset: number = 0,
    sort: string = '-name',
    search?: string,
    select?: string,
    agentId?: string,
    status?: string
  ) => {
    try {
      const params: Record<string, any> = {
        limit,
        offset,
        sort,
      };

      if (search) params.search = search;
      if (select) params.select = select;
      if (agentId) params.agent_id = agentId;
      if (status) params.status = status;

      const response = await wazuhApi.get<WazuhResponse<WazuhAgent>>('/agents', { params });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch Wazuh agents: ${error}`);
    }
  },

  // Get alerts from Wazuh Indexer
  getAlerts: async (
    limit: number = 50,
    offset: number = 0,
    sort: string = '-@timestamp',
    ruleId?: string,
    ruleLevel?: string,
    agentId?: string,
    agentName?: string,
    srcip?: string,
    dstip?: string,
    timestampGte?: string,
    timestampLte?: string,
    query?: string
  ) => {
    try {
      const params: Record<string, any> = {
        limit,
        offset,
        sort,
      };

      if (ruleId) params.rule_id = ruleId;
      if (ruleLevel) params.rule_level = ruleLevel;
      if (agentId) params.agent_id = agentId;
      if (agentName) params.agent_name = agentName;
      if (srcip) params.srcip = srcip;
      if (dstip) params.dstip = dstip;
      if (timestampGte) params.timestamp_gte = timestampGte;
      if (timestampLte) params.timestamp_lte = timestampLte;
      if (query) params.query = query;

      const response = await wazuhApi.get<WazuhResponse<WazuhAlert>>('/alerts', { params });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch Wazuh alerts: ${error}`);
    }
  },

  // Get specific alert by ID
  getAlertById: async (alertId: string) => {
    try {
      const response = await wazuhApi.get<WazuhResponse<WazuhAlert>>(`/alerts/${alertId}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch Wazuh alert by ID: ${error}`);
    }
  },
};

export default wazuhService;