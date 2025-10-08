//
//  KeyRotation.swift
//  Automated key rotation - Fixed version
//

import Foundation
import CryptoKit
import SwiftUI

// Simple Contact struct for KeyRotation if not defined elsewhere
struct KeyRotationContact {
    let publicKey: String
    let name: String
}

class KeyRotationManager: ObservableObject {
    @Published var rotationStatus: [String: RotationInfo] = [:]
    
    private let rotationInterval: TimeInterval = 7 * 24 * 60 * 60 // 7 days
    private var monitorTimer: Timer?
    
    // Constante statique pour être accessible depuis RotationInfo
    static let warningInterval: TimeInterval = 24 * 60 * 60 // 1 day before
    
    struct RotationInfo: Codable {
        let publicKey: String
        let lastRotation: Date
        let nextRotation: Date
        let rotationCount: Int
        var isOverdue: Bool {
            nextRotation < Date()
        }
        var needsWarning: Bool {
            nextRotation.timeIntervalSinceNow < KeyRotationManager.warningInterval && nextRotation.timeIntervalSinceNow > 0
        }
    }
    
    struct KeyRotationPacket: Codable {
        let oldPublicKey: String
        let newPublicKey: String
        let timestamp: Date
        let signature: Data
        let rotationNumber: Int
    }
    
    init() {
        loadRotationInfo()
        // Démarrer le monitoring après un délai pour éviter les problèmes d'initialisation
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.startRotationMonitor()
        }
    }
    
    deinit {
        monitorTimer?.invalidate()
    }
    
    // MARK: - Key Rotation
    
    func rotateKeys(for contactKey: String, walletPublicKey: String) -> Bool {
        print("🔄 Initiating key rotation for \(contactKey.prefix(8))...")
        
        let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let newPublicKey = newPrivateKey.publicKey.rawRepresentation.base64EncodedString()
        
        let packet = KeyRotationPacket(
            oldPublicKey: walletPublicKey,
            newPublicKey: newPublicKey,
            timestamp: Date(),
            signature: signRotation(oldKey: walletPublicKey, newKey: newPublicKey),
            rotationNumber: (rotationStatus[contactKey]?.rotationCount ?? 0) + 1
        )
        
        guard sendRotationPacket(packet, to: contactKey) else {
            print("❌ Failed to send rotation packet")
            return false
        }
        
        let info = RotationInfo(
            publicKey: contactKey,
            lastRotation: Date(),
            nextRotation: Date().addingTimeInterval(rotationInterval),
            rotationCount: packet.rotationNumber
        )
        
        rotationStatus[contactKey] = info
        saveRotationInfo()
        
        print("✅ Key rotation completed (rotation #\(packet.rotationNumber))")
        
        return true
    }
    
    func handleKeyRotation(_ data: Data, from senderKey: String) -> Bool {
        guard let packet = try? JSONDecoder().decode(KeyRotationPacket.self, from: data) else {
            print("❌ Failed to decode rotation packet")
            return false
        }
        
        guard verifyRotationSignature(packet) else {
            print("❌ Invalid rotation signature")
            return false
        }
        
        guard packet.oldPublicKey == senderKey else {
            print("❌ Old public key mismatch")
            return false
        }
        
        print("🔄 Processing key rotation from \(senderKey.prefix(8))...")
        print("   Old key: \(packet.oldPublicKey.prefix(16))...")
        print("   New key: \(packet.newPublicKey.prefix(16))...")
        
        let info = RotationInfo(
            publicKey: packet.newPublicKey,
            lastRotation: packet.timestamp,
            nextRotation: packet.timestamp.addingTimeInterval(rotationInterval),
            rotationCount: packet.rotationNumber
        )
        
        rotationStatus[packet.newPublicKey] = info
        saveRotationInfo()
        
        print("✅ Key rotation processed successfully")
        
        return true
    }
    
    // MARK: - Monitoring
    
    private func startRotationMonitor() {
        // Annuler l'ancien timer s'il existe
        monitorTimer?.invalidate()
        
        // Créer un nouveau timer
        monitorTimer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            self?.checkRotationStatus()
        }
        
        // Première vérification immédiate
        checkRotationStatus()
    }
    
    private func checkRotationStatus() {
        for (publicKey, info) in rotationStatus {
            if info.isOverdue {
                print("⚠️ Key rotation overdue for \(publicKey.prefix(8))...")
                sendRotationWarning(for: publicKey)
            } else if info.needsWarning {
                print("⏰ Key rotation due soon for \(publicKey.prefix(8))...")
                sendRotationReminder(for: publicKey)
            }
        }
    }
    
    // MARK: - Notifications
    
    private func sendRotationWarning(for publicKey: String) {
        NotificationCenter.default.post(
            name: NSNotification.Name("KeyRotationOverdue"),
            object: nil,
            userInfo: ["publicKey": publicKey]
        )
    }
    
    private func sendRotationReminder(for publicKey: String) {
        NotificationCenter.default.post(
            name: NSNotification.Name("KeyRotationDueSoon"),
            object: nil,
            userInfo: ["publicKey": publicKey]
        )
    }
    
    // MARK: - Cryptography
    
    private func signRotation(oldKey: String, newKey: String) -> Data {
        let combined = "\(oldKey):\(newKey)".data(using: .utf8)!
        return Data(SHA256.hash(data: combined))
    }
    
    private func verifyRotationSignature(_ packet: KeyRotationPacket) -> Bool {
        let expectedSignature = signRotation(oldKey: packet.oldPublicKey, newKey: packet.newPublicKey)
        return packet.signature == expectedSignature
    }
    
    private func sendRotationPacket(_ packet: KeyRotationPacket, to contactKey: String) -> Bool {
        guard let data = try? JSONEncoder().encode(packet) else {
            return false
        }
        
        NotificationCenter.default.post(
            name: NSNotification.Name("SendKeyRotation"),
            object: nil,
            userInfo: ["data": data, "recipient": contactKey]
        )
        
        return true
    }
    
    // MARK: - Persistence
    
    private func saveRotationInfo() {
        if let encoded = try? JSONEncoder().encode(rotationStatus) {
            UserDefaults.standard.set(encoded, forKey: "keyRotationStatus")
        }
    }
    
    private func loadRotationInfo() {
        if let data = UserDefaults.standard.data(forKey: "keyRotationStatus"),
           let decoded = try? JSONDecoder().decode([String: RotationInfo].self, from: data) {
            rotationStatus = decoded
        }
    }
    
    // MARK: - Helper Methods
    
    func needsRotation(for publicKey: String) -> Bool {
        guard let info = rotationStatus[publicKey] else {
            return false
        }
        return info.isOverdue
    }
    
    func daysUntilRotation(for publicKey: String) -> Int? {
        guard let info = rotationStatus[publicKey] else {
            return nil
        }
        let days = Int(info.nextRotation.timeIntervalSinceNow / 86400)
        return max(0, days)
    }
}

// MARK: - Key Rotation View

struct KeyRotationView: View {
    @ObservedObject var rotationManager: KeyRotationManager
    let contactKey: String
    let contactName: String
    @EnvironmentObject var walletManager: WalletManager
    @State private var showConfirmation = false
    @State private var isRotating = false
    @Environment(\.dismiss) var dismiss
    
    private var rotationInfo: KeyRotationManager.RotationInfo? {
        rotationManager.rotationStatus[contactKey]
    }
    
    var body: some View {
        NavigationView {
            List {
                Section {
                    HStack {
                        VStack(alignment: .leading) {
                            Text("Last Rotation")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                            Text(rotationInfo?.lastRotation.formatted() ?? "Never")
                                .font(.body)
                        }
                        Spacer()
                    }
                    
                    HStack {
                        VStack(alignment: .leading) {
                            Text("Next Rotation")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                            Text(rotationInfo?.nextRotation.formatted() ?? "Not scheduled")
                                .font(.body)
                                .foregroundColor(rotationInfo?.isOverdue == true ? .red : .primary)
                        }
                        Spacer()
                    }
                    
                    if let days = rotationManager.daysUntilRotation(for: contactKey) {
                        HStack {
                            VStack(alignment: .leading) {
                                Text("Status")
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                                Text("\(days) days remaining")
                                    .font(.body)
                                    .foregroundColor(days < 2 ? .orange : .green)
                            }
                            Spacer()
                        }
                    }
                } header: {
                    Text("Rotation Schedule")
                }
                
                Section {
                    Text("Regular key rotation enhances security by limiting the time window for compromised keys. We recommend rotating keys every 7 days.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                } header: {
                    Text("About Key Rotation")
                }
                
                Section {
                    Button {
                        showConfirmation = true
                    } label: {
                        HStack {
                            Image(systemName: "arrow.triangle.2.circlepath")
                            Text("Rotate Keys Now")
                            Spacer()
                        }
                    }
                    .disabled(isRotating)
                }
            }
            .navigationTitle("Key Rotation")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Rotate Encryption Keys?", isPresented: $showConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Rotate") {
                    performRotation()
                }
            } message: {
                Text("This will generate new encryption keys for \(contactName). Both devices will need to be online to complete the rotation.")
            }
        }
    }
    
    private func performRotation() {
        isRotating = true
        
        DispatchQueue.global().async {
            let success = rotationManager.rotateKeys(
                for: contactKey,
                walletPublicKey: walletManager.publicKey
            )
            
            DispatchQueue.main.async {
                isRotating = false
                if success {
                    dismiss()
                }
            }
        }
    }
}
