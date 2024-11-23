#!/usr/bin/env python
# coding: utf-8

# In[ ]:





# In[3]:


import random


# In[5]:


from collections import Counter


# In[6]:


import math


# In[12]:


def generate_packets(total_packets, legitimate_ip_count, attack_ip_count):
    """
    Generate data packets from a mix of legitimate and attack IPs.
    """
    legitimate_ips = [f"192.168.1.{i}" for i in range(1, legitimate_ip_count + 1)]
    attack_ips = [f"10.0.0.{i}" for i in range(1, attack_ip_count + 1)]

    packets = []
    for _ in range(total_packets):
        if random.random() < 0.8:  # 80% chance of legitimate traffic
            packets.append(random.choice(legitimate_ips))
        elif attack_ips:  # Only select attack IPs if they exist
            packets.append(random.choice(attack_ips))
        else:
            packets.append(random.choice(legitimate_ips))  # Default to legitimate IPs

    return packets


# In[13]:


def calculate_entropy(packets):
    """
    Calculate the Shannon entropy of the packet source IPs.
    """
    total_packets = len(packets)
    ip_counts = Counter(packets)

    entropy = -sum(
        (count / total_packets) * math.log2(count / total_packets) for count in ip_counts.values()
    )
    return entropy


# In[14]:


def detect_ddos(packets, entropy_threshold):
    """
    Detect if a DDoS attack is likely based on entropy.
    """
    entropy = calculate_entropy(packets)
    print(f"Calculated Entropy: {entropy:.4f}")
    print(f"Threshold: {entropy_threshold}")

    if entropy < entropy_threshold:
        print("DDoS Attack Detected!")
        return True
    else:
        print("No DDoS Attack Detected.")
        return False


# In[15]:


def evaluate_accuracy():
    """
    Evaluate the accuracy of detection by testing on normal and attack scenarios.
    """
    normal_packets = generate_packets(1000, legitimate_ip_count=100, attack_ip_count=0)
    attack_packets = generate_packets(1000, legitimate_ip_count=50, attack_ip_count=50)

    # Assumed entropy threshold based on observation
    entropy_threshold = 3.5

    print("Testing Normal Traffic:")
    normal_detected = detect_ddos(normal_packets, entropy_threshold)

    print("\nTesting Attack Traffic:")
    attack_detected = detect_ddos(attack_packets, entropy_threshold)

    # Calculate accuracy (ideal: no detection for normal, detection for attack)
    accuracy = ((not normal_detected) + attack_detected) / 2
    print(f"\nDetection Accuracy: {accuracy * 100:.2f}%")


# In[16]:


if __name__ == "__main__":
    evaluate_accuracy()


# In[ ]:




