"""
DQN Agent for Adaptive Response Selection in AIDRS
Implements Deep Q-Network for learning optimal response actions (allow, alert, block)
based on network event features (attack type, severity, confidence).
"""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
import random
from pathlib import Path
import json


class DQNNetwork(nn.Module):
    """Neural network for Q-value estimation."""
    def __init__(self, state_size=8, action_size=3, hidden_size=64):
        super(DQNNetwork, self).__init__()
        self.fc1 = nn.Linear(state_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, hidden_size)
        self.fc3 = nn.Linear(hidden_size, action_size)
        self.relu = nn.ReLU()
    
    def forward(self, state):
        x = self.relu(self.fc1(state))
        x = self.relu(self.fc2(x))
        return self.fc3(x)


class DQNAgent:
    """
    Deep Q-Network Agent for AIDRS response selection.
    
    State: [attack_type_encoded, severity, confidence, flow_count, packet_size, protocol_type, src_ip_encoded, dst_ip_encoded]
    Actions: 0=Allow, 1=Alert, 2=Block
    """
    
    def __init__(self, state_size=8, action_size=3, learning_rate=0.001, 
                 gamma=0.95, epsilon=1.0, epsilon_decay=0.995, epsilon_min=0.01):
        """
        Initialize DQN Agent.
        
        Args:
            state_size: Dimension of state space
            action_size: Number of possible actions (3: allow, alert, block)
            learning_rate: Learning rate for optimizer
            gamma: Discount factor for future rewards
            epsilon: Initial exploration rate
            epsilon_decay: Decay rate per episode
            epsilon_min: Minimum exploration rate
        """
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        
        # Action mapping
        self.actions = {0: "allow", 1: "alert", 2: "block"}
        self.action_names = ["allow", "alert", "block"]
        
        # Device (GPU if available, else CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Neural networks
        self.q_network = DQNNetwork(state_size, action_size).to(self.device)
        self.target_network = DQNNetwork(state_size, action_size).to(self.device)
        self.target_network.load_state_dict(self.q_network.state_dict())
        
        # Optimizer
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=learning_rate)
        self.loss_fn = nn.MSELoss()
        
        # Replay memory
        self.memory = deque(maxlen=2000)
        self.batch_size = 32
        
        # Training stats
        self.training_log = []
    
    def remember(self, state, action, reward, next_state, done):
        """Store experience in replay memory."""
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state, training=False):
        """
        Select action using epsilon-greedy strategy.
        
        Args:
            state: Current state (numpy array)
            training: If True, use exploration; if False, use greedy policy
        
        Returns:
            Action index (0, 1, or 2)
        """
        if training and random.random() < self.epsilon:
            return random.randint(0, self.action_size - 1)
        
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
        return q_values.argmax(dim=1).item()
    
    def replay(self, batch_size=None):
        """
        Train on a batch of experiences from replay memory.
        
        Args:
            batch_size: Number of samples to train on
        """
        if batch_size is None:
            batch_size = self.batch_size
        
        if len(self.memory) < batch_size:
            return 0
        
        batch = random.sample(self.memory, batch_size)
        states = np.array([exp[0] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([exp[2] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        dones = np.array([exp[4] for exp in batch])
        
        # Convert to tensors
        states = torch.FloatTensor(states).to(self.device)
        actions = torch.LongTensor(actions).to(self.device)
        rewards = torch.FloatTensor(rewards).to(self.device)
        next_states = torch.FloatTensor(next_states).to(self.device)
        dones = torch.FloatTensor(dones).to(self.device)
        
        # Q-learning update
        q_values = self.q_network(states).gather(1, actions.unsqueeze(1)).squeeze(1)
        
        with torch.no_grad():
            max_next_q = self.target_network(next_states).max(dim=1)[0]
            target_q = rewards + self.gamma * max_next_q * (1 - dones)
        
        loss = self.loss_fn(q_values, target_q)
        
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        return loss.item()
    
    def update_target_network(self):
        """Update target network with current network weights."""
        self.target_network.load_state_dict(self.q_network.state_dict())
    
    def decay_epsilon(self):
        """Decay exploration rate."""
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def save(self, filepath="dqn_agent.pt"):
        """Save model to disk."""
        checkpoint = {
            'q_network_state': self.q_network.state_dict(),
            'target_network_state': self.target_network.state_dict(),
            'optimizer_state': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'state_size': self.state_size,
            'action_size': self.action_size,
            'training_log': self.training_log
        }
        torch.save(checkpoint, filepath)
        print(f"DQN Agent saved to {filepath}")
    
    def load(self, filepath="dqn_agent.pt"):
        """Load model from disk."""
        if not Path(filepath).exists():
            print(f"Model file {filepath} not found. Starting fresh.")
            return
        
        checkpoint = torch.load(filepath, map_location=self.device)
        self.q_network.load_state_dict(checkpoint['q_network_state'])
        self.target_network.load_state_dict(checkpoint['target_network_state'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state'])
        self.epsilon = checkpoint.get('epsilon', self.epsilon)
        self.training_log = checkpoint.get('training_log', [])
        print(f"DQN Agent loaded from {filepath}")
    
    def get_stats(self):
        """Return training statistics."""
        return {
            'memory_size': len(self.memory),
            'epsilon': round(self.epsilon, 4),
            'episodes_trained': len(self.training_log),
            'avg_reward': round(np.mean([e['reward'] for e in self.training_log][-100:]), 2) if self.training_log else 0
        }


def calculate_reward(action, actual_label, confidence):
    """
    Calculate reward for RL agent action.
    
    Reward Structure:
    - +10: Block/Alert attack correctly (action != 0 AND actual_label = attack)
    - -5: Allow attack (action = 0 AND actual_label = attack)
    - +2: Allow benign traffic correctly (action = 0 AND actual_label = benign)
    - -1: Alert benign traffic (action = 1 AND actual_label = benign)
    - -3: Block benign traffic (action = 2 AND actual_label = benign)
    
    Args:
        action: Selected action (0=allow, 1=alert, 2=block)
        actual_label: Ground truth (0=benign, 1=attack)
        confidence: Confidence score of detection (0-1)
    
    Returns:
        Reward value
    """
    is_attack = actual_label == 1
    
    if is_attack:
        if action == 0:  # Allowed attack
            return -5 * confidence
        else:  # Alerted or blocked attack
            return 10 * confidence
    else:  # Benign traffic
        if action == 0:  # Allowed benign
            return 2 * confidence
        elif action == 1:  # Alerted benign
            return -1 * confidence
        else:  # Blocked benign
            return -3 * confidence
